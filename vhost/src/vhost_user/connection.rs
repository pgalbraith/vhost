// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structs for `AF_UNIX` listener and endpoint.
//!
//! The control channel of a vhost-user connection is an `AF_UNIX` byte stream. How the objects the
//! protocol hands over — the memory backing guest RAM and the vring kick/call/err notifications —
//! travel across it is platform specific: on POSIX they are descriptors attached to a message as
//! `SCM_RIGHTS` ancillary data.
//!
//! The platform-specific half of [`Endpoint`] therefore lives in [`unix`]; everything that does not
//! depend on how objects are passed is shared.

#![allow(dead_code)]

use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::{io::ErrorKind, mem, slice};

use vm_memory::ByteValued;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use super::message::*;
use super::{Error, Result};

#[cfg(unix)]
mod unix;

/// A raw handle on an object the protocol passes between peers.
///
/// This is what the send side takes for the objects it attaches to a message.
#[cfg(unix)]
pub(super) type RawDescriptor = std::os::unix::io::RawFd;

/// Unix domain socket listener for accepting incoming connections.
pub struct Listener {
    fd: UnixListener,
    path: Option<PathBuf>,
}

impl Listener {
    /// Create a unix domain socket listener.
    ///
    /// # Return:
    /// * - the new Listener object on success.
    /// * - SocketError: failed to create listener socket.
    pub fn new<P: AsRef<Path>>(path: P, unlink: bool) -> Result<Self> {
        if unlink {
            let _ = std::fs::remove_file(&path);
        }
        let fd = UnixListener::bind(&path).map_err(Error::SocketError)?;
        Ok(Listener {
            fd,
            path: Some(path.as_ref().to_owned()),
        })
    }

    /// Accept an incoming connection.
    ///
    /// # Return:
    /// * - Some(UnixStream): new UnixStream object if new incoming connection is available.
    /// * - None: no incoming connection available.
    /// * - SocketError: errors from accept().
    pub fn accept(&self) -> Result<Option<UnixStream>> {
        loop {
            match self.fd.accept() {
                Ok((socket, _addr)) => return Ok(Some(socket)),
                Err(e) => {
                    match e.kind() {
                        // No incoming connection available.
                        ErrorKind::WouldBlock => return Ok(None),
                        // New connection closed by peer.
                        ErrorKind::ConnectionAborted => return Ok(None),
                        // Interrupted by signals, retry
                        ErrorKind::Interrupted => continue,
                        _ => return Err(Error::SocketError(e)),
                    }
                }
            }
        }
    }

    /// Change blocking status on the listener.
    ///
    /// # Return:
    /// * - () on success.
    /// * - SocketError: failure from set_nonblocking().
    pub fn set_nonblocking(&self, block: bool) -> Result<()> {
        self.fd.set_nonblocking(block).map_err(Error::SocketError)
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for Listener {
    fn as_raw_fd(&self) -> RawDescriptor {
        self.fd.as_raw_fd()
    }
}

#[cfg(unix)]
impl std::os::unix::io::FromRawFd for Listener {
    unsafe fn from_raw_fd(fd: RawDescriptor) -> Self {
        Self::from(<UnixListener as std::os::unix::io::FromRawFd>::from_raw_fd(
            fd,
        ))
    }
}

impl From<UnixListener> for Listener {
    fn from(fd: UnixListener) -> Self {
        Self { fd, path: None }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// `AF_UNIX` socket endpoint for a vhost-user connection.
pub(super) struct Endpoint<H: MsgHeader> {
    sock: UnixStream,
    _h: PhantomData<H>,
}

impl<H: MsgHeader> Endpoint<H> {
    /// Create a new stream by connecting to server at `str`.
    ///
    /// # Return:
    /// * - the new Endpoint object on success.
    /// * - SocketConnect: failed to connect to peer.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        let sock = UnixStream::connect(path).map_err(Error::SocketConnect)?;
        Ok(Self::from_stream(sock))
    }

    /// Create an endpoint from a stream object.
    pub fn from_stream(sock: UnixStream) -> Self {
        Endpoint {
            sock,
            _h: PhantomData,
        }
    }

    pub fn try_clone_sock(&self) -> std::io::Result<UnixStream> {
        self.sock.try_clone()
    }

    /// Sends all bytes from scatter-gather vectors over the socket with optional attached file
    /// descriptors. Will loop until all data has been transfered.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_iovec_all(
        &mut self,
        iovs: &[&[u8]],
        fds: Option<&[RawDescriptor]>,
    ) -> Result<usize> {
        let mut data_sent = 0;
        let mut data_total = 0;
        let iov_lens: Vec<usize> = iovs.iter().map(|iov| iov.len()).collect();
        for len in &iov_lens {
            data_total += len;
        }

        while (data_total - data_sent) > 0 {
            let (nr_skip, offset) = get_sub_iovs_offset(&iov_lens, data_sent);
            let iov = &iovs[nr_skip][offset..];

            let data = &[&[iov], &iovs[(nr_skip + 1)..]].concat();
            let sfds = if data_sent == 0 { fds } else { None };

            let sent = self.send_iovec(data, sfds);
            match sent {
                Ok(0) => return Ok(data_sent),
                Ok(n) => data_sent += n,
                Err(e) => match e {
                    Error::SocketRetry(_) => {}
                    _ => return Err(e),
                },
            }
        }
        Ok(data_sent)
    }

    /// Sends bytes from a slice over the socket with optional attached file descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_slice(&mut self, data: &[u8], fds: Option<&[RawDescriptor]>) -> Result<usize> {
        self.send_iovec(&[data], fds)
    }

    /// Sends a header-only message with optional attached file descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    pub fn send_header(&mut self, hdr: &H, fds: Option<&[RawDescriptor]>) -> Result<()> {
        // SAFETY: Safe because there can't be other mutable referance to hdr.
        let iovs = unsafe {
            [slice::from_raw_parts(
                hdr as *const H as *const u8,
                mem::size_of::<H>(),
            )]
        };
        let bytes = self.send_iovec_all(&iovs[..], fds)?;
        if bytes != mem::size_of::<H>() {
            return Err(Error::PartialMessage);
        }
        Ok(())
    }

    /// Send a message with header and body. Optional file descriptors may be attached to
    /// the message.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    pub fn send_message<T: ByteValued>(
        &mut self,
        hdr: &H,
        body: &T,
        fds: Option<&[RawDescriptor]>,
    ) -> Result<()> {
        if mem::size_of::<T>() > H::MAX_MSG_SIZE {
            return Err(Error::OversizedMsg);
        }
        let bytes = self.send_iovec_all(&[hdr.as_slice(), body.as_slice()], fds)?;
        if bytes != mem::size_of::<H>() + mem::size_of::<T>() {
            return Err(Error::PartialMessage);
        }
        Ok(())
    }

    /// Send a message with header, body and payload. Optional file descriptors
    /// may also be attached to the message.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - OversizedMsg: message size is too big.
    /// * - PartialMessage: received a partial message.
    /// * - IncorrectFds: wrong number of attached fds.
    pub fn send_message_with_payload<T: ByteValued>(
        &mut self,
        hdr: &H,
        body: &T,
        payload: &[u8],
        fds: Option<&[RawDescriptor]>,
    ) -> Result<()> {
        let len = payload.len();
        if mem::size_of::<T>() > H::MAX_MSG_SIZE {
            return Err(Error::OversizedMsg);
        }
        if len > H::MAX_MSG_SIZE - mem::size_of::<T>() {
            return Err(Error::OversizedMsg);
        }
        if let Some(fd_arr) = fds {
            if fd_arr.len() > MAX_ATTACHED_FD_ENTRIES {
                return Err(Error::IncorrectFds);
            }
        }

        let total = mem::size_of::<H>() + mem::size_of::<T>() + len;
        let len = self.send_iovec_all(&[hdr.as_slice(), body.as_slice(), payload], fds)?;
        if len != total {
            return Err(Error::PartialMessage);
        }
        Ok(())
    }
}

// Given a slice of sizes and the `skip_size`, return the offset of `skip_size` in the slice.
// For example:
//     let iov_lens = vec![4, 4, 5];
//     let size = 6;
//     assert_eq!(get_sub_iovs_offset(&iov_len, size), (1, 2));
fn get_sub_iovs_offset(iov_lens: &[usize], skip_size: usize) -> (usize, usize) {
    let mut size = skip_size;
    let mut nr_skip = 0;

    for len in iov_lens {
        if size >= *len {
            size -= *len;
            nr_skip += 1;
        } else {
            break;
        }
    }
    (nr_skip, size)
}

#[cfg(all(unix, test))]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::IntoRawFd;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use vmm_sys_util::rand::rand_alphanumerics;
    use vmm_sys_util::tempfile::TempFile;

    fn temp_path() -> PathBuf {
        PathBuf::from(format!(
            "/tmp/vhost_test_{}",
            rand_alphanumerics(8).to_str().unwrap()
        ))
    }

    #[test]
    fn create_listener() {
        let path = temp_path();
        let listener = Listener::new(path, true).unwrap();

        assert!(listener.as_raw_fd() > 0);
    }

    #[test]
    fn create_listener_from_raw_fd() {
        let path = temp_path();
        let file = File::create(path).unwrap();

        // SAFETY: Safe because `file` contains a valid fd to a file just created and ownership of
        // the file descriptor is released.
        let listener = unsafe { Listener::from_raw_fd(file.into_raw_fd()) };

        assert!(listener.as_raw_fd() > 0);
    }

    #[test]
    fn accept_connection() {
        let path = temp_path();
        let listener = Listener::new(path, true).unwrap();
        listener.set_nonblocking(true).unwrap();

        // accept on a fd without incoming connection
        let conn = listener.accept().unwrap();
        assert!(conn.is_none());
    }

    #[test]
    fn send_data() {
        let path = temp_path();
        let listener = Listener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut frontend = Endpoint::<VhostUserMsgHeader<FrontendReq>>::connect(&path).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut backend = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(sock);

        let buf1 = [0x1, 0x2, 0x3, 0x4];
        let mut len = frontend.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let (bytes, buf2, _) = backend.recv_into_buf(0x1000).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..bytes]);

        len = frontend.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let (bytes, buf2, _) = backend.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        let (bytes, buf2, _) = backend.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
    }

    #[test]
    fn send_fd() {
        let path = temp_path();
        let listener = Listener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut frontend = Endpoint::<VhostUserMsgHeader<FrontendReq>>::connect(&path).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut backend = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(sock);

        let mut fd = TempFile::new().unwrap().into_file();
        write!(fd, "test").unwrap();

        // Normal case for sending/receiving file descriptors
        let buf1 = [0x1, 0x2, 0x3, 0x4];
        let len = frontend
            .send_slice(&buf1[..], Some(&[fd.as_raw_fd()]))
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, files) = backend.recv_into_buf(4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(files.is_some());
        let files = files.unwrap();
        {
            assert_eq!(files.len(), 1);
            let mut file = &files[0];
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }

        // Following communication pattern should work:
        // Sending side: data(header, body) with fds
        // Receiving side: data(header) with fds, data(body)
        let len = frontend
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, files) = backend.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        assert!(files.is_some());
        let files = files.unwrap();
        {
            assert_eq!(files.len(), 3);
            let mut file = &files[1];
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }
        let (bytes, buf2, files) = backend.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(files.is_none());

        // Following communication pattern should not work:
        // Sending side: data(header, body) with fds
        // Receiving side: data(header), data(body) with fds
        let len = frontend
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        if cfg!(any(target_os = "linux", target_os = "android")) {
            let _err = backend.recv_data(2).unwrap_err();
        } else {
            let (bytes, buf4) = backend.recv_data(2).unwrap();
            assert_eq!(bytes, 2);
            assert_eq!(&buf1[..2], &buf4[..]);
        }
        let (bytes, buf2, files) = backend.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(files.is_none());

        // Following communication pattern should work:
        // Sending side: data, data with fds
        // Receiving side: data, data with fds
        let len = frontend.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let len = frontend
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, files) = backend.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(files.is_none());

        let (bytes, buf2, files) = backend.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        assert!(files.is_some());
        let files = files.unwrap();
        {
            assert_eq!(files.len(), 3);
            let mut file = &files[1];
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }
        let (bytes, buf2, files) = backend.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(files.is_none());

        // Following communication pattern should not work:
        // Sending side: data1, data2 with fds
        // Receiving side: data + partial of data2, left of data2 with fds
        let len = frontend.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let len = frontend
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        if cfg!(any(target_os = "linux", target_os = "android")) {
            let _err = backend.recv_data(5).unwrap_err();
        } else {
            let (bytes, _) = backend.recv_data(5).unwrap();
            assert_eq!(bytes, 4);
        }

        let (bytes, _, files) = backend.recv_into_buf(0x4).unwrap();
        if cfg!(any(target_os = "linux", target_os = "android")) {
            assert_eq!(bytes, 3);
            assert!(files.is_none());
        } else {
            assert_eq!(bytes, 4);
            assert!(files.is_some());
        }

        // If the target fd array is too small, extra file descriptors will get lost.
        let len = frontend
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, _, files) = backend.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert!(files.is_some());
    }

    #[test]
    fn send_recv() {
        let path = temp_path();
        let listener = Listener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut frontend = Endpoint::<VhostUserMsgHeader<FrontendReq>>::connect(&path).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut backend = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(sock);

        let mut hdr1 =
            VhostUserMsgHeader::new(FrontendReq::GET_FEATURES, 0, mem::size_of::<u64>() as u32);
        hdr1.set_need_reply(true);
        let features1 = 0x1u64;
        frontend.send_message(&hdr1, &features1, None).unwrap();

        let mut features2 = 0u64;

        // SAFETY: Safe because features2 is valid and it's an `u64`.
        let slice = unsafe {
            slice::from_raw_parts_mut(
                (&mut features2 as *mut u64) as *mut u8,
                mem::size_of::<u64>(),
            )
        };
        let (hdr2, bytes, files) = backend.recv_body_into_buf(slice).unwrap();
        assert_eq!(hdr1, hdr2);
        assert_eq!(bytes, 8);
        assert_eq!(features1, features2);
        assert!(files.is_none());

        frontend.send_header(&hdr1, None).unwrap();
        let (hdr2, files) = backend.recv_header().unwrap();
        assert_eq!(hdr1, hdr2);
        assert!(files.is_none());
    }

    #[test]
    fn partial_message() {
        let path = temp_path();
        let listener = Listener::new(&path, true).unwrap();
        let mut frontend = UnixStream::connect(&path).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut backend = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(sock);

        write!(frontend, "a").unwrap();
        drop(frontend);
        assert!(matches!(backend.recv_header(), Err(Error::PartialMessage)));
    }

    #[test]
    fn disconnected() {
        let path = temp_path();
        let listener = Listener::new(&path, true).unwrap();
        let _ = UnixStream::connect(&path).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut backend = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(sock);

        assert!(matches!(backend.recv_header(), Err(Error::Disconnected)));
    }
}
