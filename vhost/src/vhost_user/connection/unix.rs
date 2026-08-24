// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! POSIX half of [`Endpoint`]: objects are passed as descriptors in `SCM_RIGHTS` ancillary data.

use std::fs::File;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use libc::{c_void, iovec};
use vm_memory::ByteValued;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use super::super::message::*;
use super::super::{Error, Result};
use super::{get_sub_iovs_offset, Endpoint, RawDescriptor};

impl<H: MsgHeader> Endpoint<H> {
    /// Sends bytes from scatter-gather vectors over the socket with optional attached file
    /// descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_iovec(&mut self, iovs: &[&[u8]], fds: Option<&[RawDescriptor]>) -> Result<usize> {
        let rfds = fds.unwrap_or_default();
        self.sock.send_with_fds(iovs, rfds).map_err(Into::into)
    }

    /// Reads bytes from the socket into the given scatter/gather vectors.
    ///
    /// # Return:
    /// * - (number of bytes received, buf) on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn recv_data(&mut self, len: usize) -> Result<(usize, Vec<u8>)> {
        let mut rbuf = vec![0u8; len];
        let mut iovs = [iovec {
            iov_base: rbuf.as_mut_ptr() as *mut c_void,
            iov_len: len,
        }];
        // SAFETY: Safe because we own rbuf and it's safe to fill a byte array with arbitrary data.
        let (bytes, _) = unsafe { self.sock.recv_with_fds(&mut iovs, &mut [])? };
        Ok((bytes, rbuf))
    }

    /// Reads bytes from the socket into the given scatter/gather vectors with optional attached
    /// file.
    ///
    /// The underlying communication channel is a Unix domain socket in STREAM mode. It's a little
    /// tricky to pass file descriptors through such a communication channel. Let's assume that a
    /// sender sending a message with some file descriptors attached. To successfully receive those
    /// attached file descriptors, the receiver must obey following rules:
    ///   1) file descriptors are attached to a message.
    ///   2) message(packet) boundaries must be respected on the receive side.
    ///
    /// In other words, recvmsg() operations must not cross the packet boundary, otherwise the
    /// attached file descriptors will get lost.
    /// Note that this function wraps received file descriptors as `File`.
    ///
    /// # Return:
    /// * - (number of bytes received, [received files]) on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    ///
    /// # Safety
    ///
    /// It is the callers responsibility to ensure it is safe for arbitrary data to be
    /// written to the iovec pointers.
    pub unsafe fn recv_into_iovec(
        &mut self,
        iovs: &mut [iovec],
    ) -> Result<(usize, Option<Vec<File>>)> {
        let mut fd_array = vec![0; MAX_ATTACHED_FD_ENTRIES];
        let (bytes, fds) = self.sock.recv_with_fds(iovs, &mut fd_array)?;

        let files = match fds {
            0 => None,
            n => {
                let files = fd_array
                    .iter()
                    .take(n)
                    .map(|fd| {
                        // Safe because we have the ownership of `fd`.
                        File::from_raw_fd(*fd)
                    })
                    .collect();
                Some(files)
            }
        };

        Ok((bytes, files))
    }

    /// Reads all bytes from the socket into the given scatter/gather vectors with optional
    /// attached files. Will loop until all data has been transferred.
    ///
    /// The underlying communication channel is a Unix domain socket in STREAM mode. It's a little
    /// tricky to pass file descriptors through such a communication channel. Let's assume that a
    /// sender sending a message with some file descriptors attached. To successfully receive those
    /// attached file descriptors, the receiver must obey following rules:
    ///   1) file descriptors are attached to a message.
    ///   2) message(packet) boundaries must be respected on the receive side.
    ///
    /// In other words, recvmsg() operations must not cross the packet boundary, otherwise the
    /// attached file descriptors will get lost.
    /// Note that this function wraps received file descriptors as `File`.
    ///
    /// # Return:
    /// * - (number of bytes received, [received fds]) on success
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    ///
    /// # Safety
    ///
    /// It is the callers responsibility to ensure it is safe for arbitrary data to be
    /// written to the iovec pointers.
    pub unsafe fn recv_into_iovec_all(
        &mut self,
        iovs: &mut [iovec],
    ) -> Result<(usize, Option<Vec<File>>)> {
        let mut data_read = 0;
        let mut data_total = 0;
        let mut rfds = None;
        let iov_lens: Vec<usize> = iovs.iter().map(|iov| iov.iov_len).collect();
        for len in &iov_lens {
            data_total += len;
        }

        while (data_total - data_read) > 0 {
            let (nr_skip, offset) = get_sub_iovs_offset(&iov_lens, data_read);
            let iov = &mut iovs[nr_skip];

            let mut data = [
                &[iovec {
                    iov_base: (iov.iov_base as usize + offset) as *mut c_void,
                    iov_len: iov.iov_len - offset,
                }],
                &iovs[(nr_skip + 1)..],
            ]
            .concat();

            let res = self.recv_into_iovec(&mut data);
            match res {
                Ok((0, _)) => return Ok((data_read, rfds)),
                Ok((n, fds)) => {
                    if data_read == 0 {
                        rfds = fds;
                    }
                    data_read += n;
                }
                Err(e) => match e {
                    Error::SocketRetry(_) => {}
                    _ => return Err(e),
                },
            }
        }
        Ok((data_read, rfds))
    }

    /// Reads bytes from the socket into a new buffer with optional attached
    /// files. Received file descriptors are set close-on-exec and converted to `File`.
    ///
    /// # Return:
    /// * - (number of bytes received, buf, [received files]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn recv_into_buf(
        &mut self,
        buf_size: usize,
    ) -> Result<(usize, Vec<u8>, Option<Vec<File>>)> {
        let mut buf = vec![0u8; buf_size];
        let (bytes, files) = {
            let mut iovs = [iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf_size,
            }];
            // SAFETY: Safe because we own buf and it's safe to fill a byte array with arbitrary data.
            unsafe { self.recv_into_iovec(&mut iovs)? }
        };
        Ok((bytes, buf, files))
    }

    /// Receive a header-only message with optional attached files.
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    ///
    /// # Return:
    /// * - (message header, [received files]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    pub fn recv_header(&mut self) -> Result<(H, Option<Vec<File>>)> {
        let mut hdr = H::default();
        let mut iovs = [iovec {
            iov_base: (&mut hdr as *mut H) as *mut c_void,
            iov_len: mem::size_of::<H>(),
        }];
        // SAFETY: Safe because we own hdr and it's ByteValued.
        let (bytes, files) = unsafe { self.recv_into_iovec_all(&mut iovs[..])? };

        if bytes == 0 {
            return Err(Error::Disconnected);
        } else if bytes != mem::size_of::<H>() {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, files))
    }

    /// Receive a message with optional attached file descriptors.
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    ///
    /// # Return:
    /// * - (message header, message body, [received files]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    pub fn recv_body<T: ByteValued + Sized + VhostUserMsgValidator + Default>(
        &mut self,
    ) -> Result<(H, T, Option<Vec<File>>)> {
        let mut hdr = H::default();
        let mut body: T = Default::default();
        let mut iovs = [
            iovec {
                iov_base: (&mut hdr as *mut H) as *mut c_void,
                iov_len: mem::size_of::<H>(),
            },
            iovec {
                iov_base: (&mut body as *mut T) as *mut c_void,
                iov_len: mem::size_of::<T>(),
            },
        ];
        // SAFETY: Safe because we own hdr and body and they're ByteValued.
        let (bytes, files) = unsafe { self.recv_into_iovec_all(&mut iovs[..])? };

        let total = mem::size_of::<H>() + mem::size_of::<T>();
        if bytes != total {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, body, files))
    }

    /// Receive a message with header and optional content. Callers need to
    /// pre-allocate a big enough buffer to receive the message body and
    /// optional payload. If there are attached file descriptor associated
    /// with the message, the first MAX_ATTACHED_FD_ENTRIES file descriptors
    /// will be accepted and all other file descriptor will be discard
    /// silently.
    ///
    /// # Return:
    /// * - (message header, message size, [received files]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    pub fn recv_body_into_buf(&mut self, buf: &mut [u8]) -> Result<(H, usize, Option<Vec<File>>)> {
        let mut hdr = H::default();
        let mut iovs = [
            iovec {
                iov_base: (&mut hdr as *mut H) as *mut c_void,
                iov_len: mem::size_of::<H>(),
            },
            iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            },
        ];
        // SAFETY: Safe because we own hdr and have a mutable borrow of buf, and hdr is ByteValued
        // and it's safe to fill a byte slice with arbitrary data.
        let (bytes, files) = unsafe { self.recv_into_iovec_all(&mut iovs[..])? };

        if bytes < mem::size_of::<H>() {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, bytes - mem::size_of::<H>(), files))
    }

    /// Receive a message with optional payload and attached file descriptors.
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    ///
    /// # Return:
    /// * - (message header, message body, size of payload, [received files]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    #[allow(clippy::type_complexity)]
    pub fn recv_payload_into_buf<T: ByteValued + Sized + VhostUserMsgValidator + Default>(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(H, T, usize, Option<Vec<File>>)> {
        let mut hdr = H::default();
        let mut body: T = Default::default();
        let mut iovs = [
            iovec {
                iov_base: (&mut hdr as *mut H) as *mut c_void,
                iov_len: mem::size_of::<H>(),
            },
            iovec {
                iov_base: (&mut body as *mut T) as *mut c_void,
                iov_len: mem::size_of::<T>(),
            },
            iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            },
        ];
        // SAFETY: Safe because we own hdr and body and have a mutable borrow of buf, and
        // hdr and body are ByteValued, and it's safe to fill a byte slice with
        // arbitrary data.
        let (bytes, files) = unsafe { self.recv_into_iovec_all(&mut iovs[..])? };

        let total = mem::size_of::<H>() + mem::size_of::<T>();
        if bytes < total {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, body, bytes - total, files))
    }
}

impl<H: MsgHeader> AsRawFd for Endpoint<H> {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}
