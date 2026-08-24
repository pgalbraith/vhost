// Copyright (C) 2026 Paul Galbraith. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows half of [`Endpoint`]: objects are passed by name in a trailer on the message payload.
//!
//! The control channel is the same `AF_UNIX` byte stream as on POSIX, and no extra framing is
//! needed: the header's `size` field covers the name trailer, so a message and the names it carries
//! arrive together. What does change is *when* the objects become available. On POSIX they are
//! ancillary data on the packet carrying the header, so `recv_header()` returns them; here they sit
//! at the end of the payload, so the payload has to be read in full before the header can be handed
//! over. `recv_header()` therefore reads the whole message, resolves the names, and keeps the
//! remaining payload in `Endpoint::pending` for the `recv_*` calls that follow — which is exactly
//! the order in which callers already use this API.
//!
//! Callers see a message identical to the one a POSIX peer would have sent: the trailer is removed
//! from the payload and from the header's `size`.
//!
//! See the [`win32`](super::super::win32) module for the wire format and why it exists.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::{mem, slice};

use vm_memory::ByteValued;

use super::super::message::*;
use super::super::win32::take_named_objects;
use super::super::{Error, Result};
use super::{Endpoint, RawDescriptor};

impl<H: MsgHeader> Endpoint<H> {
    /// Sends bytes from scatter-gather vectors over the socket.
    ///
    /// Windows cannot attach objects to a message, so `fds` must be empty or absent; the protocol
    /// names objects in the payload instead.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - InvalidOperation: descriptors were attached to the message.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_iovec(&mut self, iovs: &[&[u8]], fds: Option<&[RawDescriptor]>) -> Result<usize> {
        if matches!(fds, Some(fds) if !fds.is_empty()) {
            return Err(Error::InvalidOperation(
                "attaching descriptors to a message is not supported on Windows",
            ));
        }

        let data = iovs.concat();
        self.sock.write_all(&data).map_err(Error::SocketError)?;
        Ok(data.len())
    }

    /// Read into `buf` until it is full or the peer stops sending, returning the number of bytes
    /// read. A short read means the peer disconnected mid-message; zero means it disconnected
    /// before sending any of it.
    fn read_all(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut read = 0;

        while read < buf.len() {
            match self.sock.read(&mut buf[read..]) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::SocketError(e)),
            }
        }

        Ok(read)
    }

    /// Receive a message header, together with the objects the message passes.
    ///
    /// This reads the message in full — see the module docs for why — so the `recv_*` calls that
    /// follow are served from the buffered payload rather than from the socket.
    ///
    /// # Return:
    /// * - (message header, [received objects]) on success.
    /// * - Disconnected: the peer closed the connection.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received an invalid message.
    /// * - OversizedMsg: the header claims a payload larger than the protocol allows.
    /// * - Win32ObjectOpen: a named object could not be opened.
    /// * - SocketError: other socket related errors.
    pub fn recv_header(&mut self) -> Result<(H, Option<Vec<File>>)> {
        self.pending.clear();

        let mut hdr = H::default();
        // SAFETY: `H` is `ByteValued`, so it is safe to fill with arbitrary data.
        let hdr_buf = unsafe {
            slice::from_raw_parts_mut(&mut hdr as *mut H as *mut u8, mem::size_of::<H>())
        };
        match self.read_all(hdr_buf)? {
            0 => return Err(Error::Disconnected),
            n if n != mem::size_of::<H>() => return Err(Error::PartialMessage),
            _ => {}
        }
        if !hdr.is_valid() {
            return Err(Error::InvalidMessage);
        }

        let size = hdr.get_size() as usize;
        if size > H::MAX_MSG_SIZE {
            return Err(Error::OversizedMsg);
        }
        let mut payload = vec![0u8; size];
        if self.read_all(&mut payload)? != size {
            return Err(Error::PartialMessage);
        }

        let (count, kind) = hdr.win32_name_trailer(&payload)?;
        let (base, files) = take_named_objects(&payload, count, kind)?;

        // Hide the trailer from callers, so that the message they see is the one a POSIX peer would
        // have sent.
        let base_len = base.len();
        hdr.set_size(base_len as u32);
        payload.truncate(base_len);
        self.pending = payload;

        Ok((hdr, if files.is_empty() { None } else { Some(files) }))
    }

    /// Read up to `len` bytes of the current message's payload.
    ///
    /// `buf` is always `len` bytes long, zero padded past the bytes that were available.
    ///
    /// # Return:
    /// * - (number of bytes available, buf) on success.
    pub fn recv_data(&mut self, len: usize) -> Result<(usize, Vec<u8>)> {
        let bytes = std::cmp::min(len, self.pending.len());
        let mut buf: Vec<u8> = self.pending.drain(..bytes).collect();
        buf.resize(len, 0);

        Ok((bytes, buf))
    }

    /// Receive a message with a fixed size body, together with the objects it passes.
    ///
    /// # Return:
    /// * - (message header, message body, [received objects]) on success.
    /// * - Disconnected: the peer closed the connection.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received an invalid message.
    /// * - SocketError: other socket related errors.
    pub fn recv_body<T: ByteValued + Sized + VhostUserMsgValidator + Default>(
        &mut self,
    ) -> Result<(H, T, Option<Vec<File>>)> {
        let (hdr, files) = self.recv_header()?;
        let body = self.take_body::<T>()?;
        if !self.pending.is_empty() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, body, files))
    }

    /// Receive a message with an optional payload, together with the objects it passes.
    ///
    /// # Return:
    /// * - (message header, size of payload, [received objects]) on success.
    /// * - Disconnected: the peer closed the connection.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received an invalid message.
    /// * - SocketError: other socket related errors.
    pub fn recv_body_into_buf(&mut self, buf: &mut [u8]) -> Result<(H, usize, Option<Vec<File>>)> {
        let (hdr, files) = self.recv_header()?;
        let len = self.take_payload(buf)?;

        Ok((hdr, len, files))
    }

    /// Receive a message with a fixed size body and an optional payload, together with the objects
    /// it passes.
    ///
    /// # Return:
    /// * - (message header, message body, size of payload, [received objects]) on success.
    /// * - Disconnected: the peer closed the connection.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received an invalid message.
    /// * - SocketError: other socket related errors.
    #[allow(clippy::type_complexity)]
    pub fn recv_payload_into_buf<T: ByteValued + Sized + VhostUserMsgValidator + Default>(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(H, T, usize, Option<Vec<File>>)> {
        let (hdr, files) = self.recv_header()?;
        let body = self.take_body::<T>()?;
        let len = self.take_payload(buf)?;

        Ok((hdr, body, len, files))
    }

    /// Receive a whole message payload into a new buffer, together with the objects it passes.
    ///
    /// # Return:
    /// * - (number of bytes received, buf, [received objects]) on success.
    /// * - Disconnected: the peer closed the connection.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received an invalid message.
    /// * - SocketError: other socket related errors.
    pub fn recv_into_buf(
        &mut self,
        buf_size: usize,
    ) -> Result<(usize, Vec<u8>, Option<Vec<File>>)> {
        let mut buf = vec![0u8; buf_size];
        let (_, files) = self.recv_header()?;
        let len = self.take_payload(&mut buf)?;

        Ok((len, buf, files))
    }

    /// Take a fixed size body off the front of the buffered payload.
    fn take_body<T: ByteValued + Sized + VhostUserMsgValidator + Default>(&mut self) -> Result<T> {
        let (bytes, buf) = self.recv_data(mem::size_of::<T>())?;
        if bytes != mem::size_of::<T>() {
            return Err(Error::PartialMessage);
        }

        // SAFETY: `T` is `ByteValued` and `buf` is exactly `size_of::<T>()` bytes long.
        let body: T = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) };
        if !body.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok(body)
    }

    /// Take the rest of the buffered payload, which must fit in `buf`.
    fn take_payload(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = self.pending.len();
        if len > buf.len() {
            return Err(Error::OversizedMsg);
        }
        buf[..len].copy_from_slice(&self.pending);
        self.pending.clear();

        Ok(len)
    }
}

impl<H: MsgHeader> AsRawSocket for Endpoint<H> {
    fn as_raw_socket(&self) -> RawSocket {
        self.sock.as_raw_socket()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use uds_windows::UnixStream;
    use windows_sys::Win32::System::Memory::{CreateFileMappingA, PAGE_READWRITE};
    use windows_sys::Win32::System::Threading::CreateEventA;

    use super::super::super::win32::VHOST_USER_WIN32_NAME_SIZE;
    use super::*;

    /// A named kernel object, kept alive for as long as a test needs the name to resolve.
    struct NamedObject {
        name: Vec<u8>,
        handle: std::os::windows::io::RawHandle,
    }

    impl NamedObject {
        /// Build a name that cannot collide with a concurrent test or another process.
        fn name_for(kind: &str, seq: u32) -> Vec<u8> {
            let mut name = format!(
                r"Local\vhost-rs-test-{}-{}-{}",
                std::process::id(),
                kind,
                seq
            )
            .into_bytes();
            assert!(name.len() < VHOST_USER_WIN32_NAME_SIZE);
            name.push(0);
            name
        }

        fn event(seq: u32) -> Self {
            let name = Self::name_for("evt", seq);
            // SAFETY: `name` is NUL-terminated and outlives the call.
            let handle = unsafe { CreateEventA(std::ptr::null(), 1, 0, name.as_ptr()) };
            assert!(!handle.is_null(), "{}", std::io::Error::last_os_error());
            NamedObject { name, handle }
        }

        fn section(seq: u32) -> Self {
            let name = Self::name_for("ram", seq);
            // SAFETY: `name` is NUL-terminated and outlives the call. A null file handle asks for a
            // pagefile-backed section, which is what a shared guest RAM block is.
            let handle = unsafe {
                CreateFileMappingA(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    PAGE_READWRITE,
                    0,
                    0x1000,
                    name.as_ptr(),
                )
            };
            assert!(!handle.is_null(), "{}", std::io::Error::last_os_error());
            NamedObject { name, handle }
        }

        /// The name as it travels on the wire: NUL-terminated, NUL-padded to a fixed size.
        fn record(&self) -> Vec<u8> {
            let mut record = self.name.clone();
            record.resize(VHOST_USER_WIN32_NAME_SIZE, 0);
            record
        }
    }

    impl Drop for NamedObject {
        fn drop(&mut self) {
            // SAFETY: `handle` is a live handle this struct owns.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
        }
    }

    /// Write one message, trailer included, and read it back through an `Endpoint`.
    fn round_trip(
        code: FrontendReq,
        body: &[u8],
        trailer: &[u8],
    ) -> (
        VhostUserMsgHeader<FrontendReq>,
        Option<Vec<File>>,
        Endpoint<VhostUserMsgHeader<FrontendReq>>,
    ) {
        let (mut frontend, backend) = UnixStream::pair().unwrap();
        let size = (body.len() + trailer.len()) as u32;
        let hdr = VhostUserMsgHeader::new(code, 0, size);

        frontend.write_all(hdr.as_slice()).unwrap();
        frontend.write_all(body).unwrap();
        frontend.write_all(trailer).unwrap();

        let mut endpoint = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(backend);
        let (hdr, files) = endpoint.recv_header().unwrap();
        (hdr, files, endpoint)
    }

    #[test]
    fn vring_kick_opens_named_event() {
        let event = NamedObject::event(0);
        let body = VhostUserU64::new(0);
        let (hdr, files, mut endpoint) = round_trip(
            FrontendReq::SET_VRING_KICK,
            body.as_slice(),
            &event.record(),
        );

        // The trailer is hidden from callers: what they see is the message a POSIX peer would have
        // sent, with the object delivered alongside it.
        assert_eq!(hdr.get_size() as usize, mem::size_of::<VhostUserU64>());
        assert_eq!(files.unwrap().len(), 1);

        let (bytes, buf) = endpoint.recv_data(mem::size_of::<VhostUserU64>()).unwrap();
        assert_eq!(bytes, mem::size_of::<VhostUserU64>());
        assert_eq!(buf, body.as_slice());
    }

    // With VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS negotiated the frontend stops sending
    // SET_MEM_TABLE and grows the table one region at a time instead. ADD_MEM_REG names a section;
    // REM_MEM_REG carries no object on either platform, so it has no trailer.
    #[test]
    fn add_mem_reg_opens_named_section() {
        let section = NamedObject::section(2);
        let body = VhostUserSingleMemoryRegion::new(0, 0x1000, 0, 0);
        let (hdr, files, _) =
            round_trip(FrontendReq::ADD_MEM_REG, body.as_slice(), &section.record());

        assert_eq!(
            hdr.get_size() as usize,
            mem::size_of::<VhostUserSingleMemoryRegion>()
        );
        assert_eq!(files.unwrap().len(), 1);
    }

    #[test]
    fn rem_mem_reg_has_no_trailer() {
        let body = VhostUserSingleMemoryRegion::new(0, 0x1000, 0, 0);
        let (hdr, files, _) = round_trip(FrontendReq::REM_MEM_REG, body.as_slice(), &[]);

        assert_eq!(
            hdr.get_size() as usize,
            mem::size_of::<VhostUserSingleMemoryRegion>()
        );
        assert!(files.is_none());
    }

    #[test]
    fn vring_kick_without_object() {
        let body = VhostUserU64::new(VHOST_USER_VRING_NOFD_MASK);
        let (hdr, files, _) = round_trip(FrontendReq::SET_VRING_KICK, body.as_slice(), &[]);

        assert_eq!(hdr.get_size() as usize, mem::size_of::<VhostUserU64>());
        assert!(files.is_none());
    }

    #[test]
    fn mem_table_opens_one_section_per_region() {
        // Both regions name the same section at different offsets, which is what a single shared
        // guest RAM block looks like on the wire.
        let section = NamedObject::section(1);
        let regions = [
            VhostUserMemoryRegion::new(0, 0x800, 0, 0),
            VhostUserMemoryRegion::new(0x800, 0x800, 0, 0x800),
        ];

        let mut body = VhostUserMemory::new(regions.len() as u32)
            .as_slice()
            .to_vec();
        for region in &regions {
            body.extend_from_slice(region.as_slice());
        }
        let trailer: Vec<u8> = regions.iter().flat_map(|_| section.record()).collect();

        let (hdr, files, _) = round_trip(FrontendReq::SET_MEM_TABLE, &body, &trailer);

        assert_eq!(hdr.get_size() as usize, body.len());
        assert_eq!(files.unwrap().len(), regions.len());
    }

    #[test]
    fn unknown_name_is_reported() {
        let mut record = br"Local\vhost-rs-test-does-not-exist".to_vec();
        record.push(0);
        record.resize(VHOST_USER_WIN32_NAME_SIZE, 0);
        let body = VhostUserU64::new(0);

        let (mut frontend, backend) = UnixStream::pair().unwrap();
        let size = (body.as_slice().len() + record.len()) as u32;
        let hdr = VhostUserMsgHeader::new(FrontendReq::SET_VRING_KICK, 0, size);
        frontend.write_all(hdr.as_slice()).unwrap();
        frontend.write_all(body.as_slice()).unwrap();
        frontend.write_all(&record).unwrap();

        let mut endpoint = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(backend);
        assert!(matches!(
            endpoint.recv_header(),
            Err(Error::Win32ObjectOpen(_))
        ));
    }

    #[test]
    fn attaching_descriptors_is_rejected() {
        let (_frontend, backend) = UnixStream::pair().unwrap();
        let mut endpoint = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(backend);
        let hdr = VhostUserMsgHeader::new(FrontendReq::SET_VRING_KICK, 0, 0);

        assert!(matches!(
            endpoint.send_header(&hdr, Some(&[std::ptr::null_mut()])),
            Err(Error::InvalidOperation(_))
        ));
    }
}
