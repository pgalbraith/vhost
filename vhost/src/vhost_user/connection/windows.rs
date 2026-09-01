// Copyright (C) 2026 Paul Galbraith. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows half of [`Endpoint`]: objects travel as handle records in a trailer on the message
//! payload, `DuplicateHandle` standing in for `SCM_RIGHTS`.
//!
//! Same `AF_UNIX` byte stream as POSIX, no extra framing needed — the header's `size` covers the
//! trailer, so message and handles arrive together. What changes is *when* objects become
//! available: on POSIX they ride with the header as ancillary data, but here they sit at the
//! payload's end, so the whole message must be read before the header can be handed back.
//! `recv_header()` does that: reads the message, takes ownership of the handles, and buffers the
//! rest in `Endpoint::pending` for the `recv_*` calls that follow.
//!
//! The frontend and backend halves of a connection differ, because every handle value on the wire
//! is relative to the *backend* process. A frontend endpoint holds a handle to the backend
//! process (`Endpoint::set_peer_process`); `send_iovec` duplicates each attached object into the
//! backend through it and appends the records the backend will adopt as they are. A backend
//! endpoint holds nothing extra and never sends objects: every message that would carry a handle
//! back to the frontend belongs to a feature not negotiated on Windows.
//!
//! Callers see the same message a POSIX peer would have sent — trailer stripped from both payload
//! and header `size`, objects delivered alongside as on POSIX.
//!
//! See [`win32`](super::super::win32) for the wire format and why it exists.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::windows::io::{AsHandle, AsRawSocket, OwnedHandle, RawSocket};
use std::{mem, slice};

use vm_memory::ByteValued;

use super::super::message::*;
use super::super::win32::{close_in_peer, duplicate_into_peer, take_handles};
use super::super::{Error, Result};
use super::{Endpoint, RawDescriptor};

impl<H: MsgHeader> Endpoint<H> {
    /// Make this the frontend end of the connection: a handle to the backend process, with
    /// `PROCESS_DUP_HANDLE` access, that objects are duplicated into on send and pulled out of on
    /// receive. Held for the connection's lifetime.
    pub fn set_peer_process(&mut self, process: OwnedHandle) {
        self.peer_process = Some(process);
    }

    /// Sends bytes from scatter-gather vectors over the socket, handing over the objects in `fds`
    /// through the message itself.
    ///
    /// Windows sockets carry no ancillary data, so each object is duplicated into the peer process
    /// and the resulting handle values are appended to the message as trailer records, with the
    /// header's `size` grown to cover them. That needs the peer's process handle, which only the
    /// frontend side holds (see `set_peer_process`); a backend has nothing to send this way in any
    /// case, since every message that would carry a handle back to the frontend belongs to a
    /// feature not negotiated on Windows.
    ///
    /// The returned count excludes the trailer, so callers can balance it against the bytes they
    /// passed in, exactly as on POSIX where the descriptors are not part of the byte stream.
    ///
    /// # Return:
    /// * - number of bytes sent, trailer not counted, on success
    /// * - InvalidOperation: descriptors were attached without a peer process handle.
    /// * - Win32HandleTransfer: a descriptor could not be duplicated into the peer.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_iovec(&mut self, iovs: &[&[u8]], fds: Option<&[RawDescriptor]>) -> Result<usize> {
        let handles = fds.unwrap_or_default();
        let mut data = iovs.concat();
        if handles.is_empty() {
            self.sock.write_all(&data).map_err(Error::SocketError)?;
            return Ok(data.len());
        }

        let Some(peer) = self.peer_process.as_ref() else {
            return Err(Error::InvalidOperation(
                "sending objects needs the backend process handle, which only the frontend holds",
            ));
        };
        let peer = peer.as_handle();

        // Every sender in `connection.rs` puts the full header first, so the `size` field to grow
        // is at the front of `data`.
        if data.len() < mem::size_of::<H>() {
            return Err(Error::InvalidParam);
        }

        let trailer = duplicate_into_peer(peer, handles)?;

        // SAFETY: `H` is `ByteValued` and `data` holds at least `size_of::<H>()` bytes of it.
        let mut hdr: H = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const H) };
        hdr.set_size(hdr.get_size() + trailer.len() as u32);
        data[..mem::size_of::<H>()].copy_from_slice(hdr.as_slice());

        let sent = data.len();
        data.extend_from_slice(&trailer);
        if let Err(e) = self.sock.write_all(&data) {
            // An SCM_RIGHTS send that fails delivers nothing. Duplication already happened, so
            // restore that property by hand: take the handles back out of the peer, which was
            // never told of them and could otherwise never release the objects.
            close_in_peer(peer, &trailer);
            return Err(Error::SocketError(e));
        }
        Ok(sent)
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
    /// * - Win32InvalidHandle: a handle record was not a live handle here.
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

        let count = hdr.win32_handle_trailer(&payload)?;
        let peer = self.peer_process.as_ref().map(|p| p.as_handle());
        let (base, files) = take_handles(peer, &payload, count)?;

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
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE,
    };
    use windows_sys::Win32::System::Memory::{CreateFileMappingA, PAGE_READWRITE};
    use windows_sys::Win32::System::Threading::{CreateEventA, GetCurrentProcess};

    use super::*;

    /// A kernel object standing in for one the frontend owns. Unnamed, as the binding requires:
    /// the peer only ever gets to it through a duplicated handle.
    struct SharedObject {
        handle: HANDLE,
    }

    impl SharedObject {
        fn event() -> Self {
            // SAFETY: all arguments are simple values; the result is checked.
            let handle = unsafe { CreateEventA(std::ptr::null(), 1, 0, std::ptr::null()) };
            assert!(!handle.is_null(), "{}", std::io::Error::last_os_error());
            SharedObject { handle }
        }

        fn section() -> Self {
            // SAFETY: a null file handle asks for a pagefile-backed section, which is what a
            // shared guest RAM block is; the result is checked.
            let handle = unsafe {
                CreateFileMappingA(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    PAGE_READWRITE,
                    0,
                    0x1000,
                    std::ptr::null(),
                )
            };
            assert!(!handle.is_null(), "{}", std::io::Error::last_os_error());
            SharedObject { handle }
        }

        /// What the frontend puts on the wire: the object duplicated into the peer — here, this
        /// same process — as an 8-byte handle value.
        fn record(&self) -> Vec<u8> {
            let mut dup: HANDLE = std::ptr::null_mut();
            // SAFETY: both process handles are the current-process pseudo handle, `self.handle` is
            // live, and `dup` is a valid out-pointer.
            let ok = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    self.handle,
                    GetCurrentProcess(),
                    &mut dup,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            assert!(ok != 0, "{}", std::io::Error::last_os_error());
            (dup as usize as u64).to_le_bytes().to_vec()
        }
    }

    impl Drop for SharedObject {
        fn drop(&mut self) {
            // SAFETY: `handle` is a live handle this struct owns.
            unsafe { CloseHandle(self.handle) };
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
    fn vring_kick_adopts_an_event() {
        let event = SharedObject::event();
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
    // SET_MEM_TABLE and grows the table one region at a time instead. ADD_MEM_REG carries a
    // section; REM_MEM_REG carries no object on either platform, so it has no trailer.
    #[test]
    fn add_mem_reg_adopts_a_section() {
        let section = SharedObject::section();
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
    fn mem_table_adopts_one_section_per_region() {
        // Both regions come from the same section at different offsets, which is what a single
        // shared guest RAM block looks like on the wire: one duplicate per region.
        let section = SharedObject::section();
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
    fn an_unusable_handle_is_reported() {
        let record = 0xdead_beef_u64.to_le_bytes().to_vec();
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
            Err(Error::Win32InvalidHandle(_))
        ));
    }

    #[test]
    fn attaching_descriptors_needs_a_peer_process() {
        let (_frontend, backend) = UnixStream::pair().unwrap();
        let mut endpoint = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(backend);
        let hdr = VhostUserMsgHeader::new(FrontendReq::SET_VRING_KICK, 0, 0);

        assert!(matches!(
            endpoint.send_header(&hdr, Some(&[0])),
            Err(Error::InvalidOperation(_))
        ));
    }

    /// A connected endpoint pair, the frontend end armed with the "backend process" handle —
    /// this same process, so both ends can be driven from one test.
    fn endpoint_pair() -> (
        Endpoint<VhostUserMsgHeader<FrontendReq>>,
        Endpoint<VhostUserMsgHeader<FrontendReq>>,
    ) {
        let (f, b) = UnixStream::pair().unwrap();
        let mut frontend = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(f);
        frontend.set_peer_process(super::super::super::win32::current_process());
        (frontend, Endpoint::from_stream(b))
    }

    fn is_signaled(handle: HANDLE) -> bool {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        // SAFETY: the caller passes a live handle.
        match unsafe { WaitForSingleObject(handle, 0) } {
            WAIT_OBJECT_0 => true,
            WAIT_TIMEOUT => false,
            other => panic!("unexpected wait result {other:#x}"),
        }
    }

    #[test]
    fn frontend_hands_an_event_over_inside_the_message() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::SetEvent;

        let (mut frontend, mut backend) = endpoint_pair();
        let event = SharedObject::event();
        let body = VhostUserU64::new(0);
        let hdr = VhostUserMsgHeader::new(
            FrontendReq::SET_VRING_KICK,
            0,
            mem::size_of::<VhostUserU64>() as u32,
        );
        frontend
            .send_message(&hdr, &body, Some(&[event.handle as _]))
            .unwrap();

        // The backend sees the POSIX-shaped message with the object alongside — the endpoint
        // grew `size` for the trailer on the way out and the receiver stripped it again.
        let (rhdr, files) = backend.recv_header().unwrap();
        assert_eq!(rhdr.get_size() as usize, mem::size_of::<VhostUserU64>());
        let files = files.unwrap();
        assert_eq!(files.len(), 1);

        // The received object is the sent one, held through an independent handle.
        assert!(!is_signaled(files[0].as_raw_handle() as HANDLE));
        // SAFETY: `event.handle` is a live event handle.
        unsafe { SetEvent(event.handle) };
        assert!(is_signaled(files[0].as_raw_handle() as HANDLE));
    }

    #[test]
    fn frontend_hands_a_section_over_per_region() {
        let (mut frontend, mut backend) = endpoint_pair();
        let section = SharedObject::section();
        let regions = [
            VhostUserMemoryRegion::new(0, 0x800, 0, 0),
            VhostUserMemoryRegion::new(0x800, 0x800, 0, 0x800),
        ];
        let body = VhostUserMemory::new(regions.len() as u32);
        let payload: Vec<u8> = regions.iter().flat_map(|r| r.as_slice().to_vec()).collect();
        let hdr = VhostUserMsgHeader::new(
            FrontendReq::SET_MEM_TABLE,
            0,
            (mem::size_of::<VhostUserMemory>() + payload.len()) as u32,
        );
        frontend
            .send_message_with_payload(
                &hdr,
                &body,
                &payload,
                Some(&[section.handle as _, section.handle as _]),
            )
            .unwrap();

        let (rhdr, files) = backend.recv_header().unwrap();
        assert_eq!(
            rhdr.get_size() as usize,
            mem::size_of::<VhostUserMemory>() + payload.len()
        );
        assert_eq!(files.unwrap().len(), regions.len());
    }

    // A REPLY_ACK ack echoes the request code, so an ack for SET_VRING_KICK must not be read as
    // carrying the record only the request has. Regression test for the reply guard in
    // `MsgHeader::win32_handle_trailer`.
    #[test]
    fn frontend_reads_a_reply_ack_without_expecting_a_trailer() {
        let (mut frontend, mut backend) = endpoint_pair();
        let mut hdr = VhostUserMsgHeader::new(
            FrontendReq::SET_VRING_KICK,
            0,
            mem::size_of::<VhostUserU64>() as u32,
        );
        hdr.set_reply(true);
        let ack = VhostUserU64::new(0);
        backend.send_message(&hdr, &ack, None).unwrap();

        let (rhdr, body, files) = frontend.recv_body::<VhostUserU64>().unwrap();
        assert!(rhdr.is_reply());
        assert_eq!(body.value, 0);
        assert!(files.is_none());
    }
}
