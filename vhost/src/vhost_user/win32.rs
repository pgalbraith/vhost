// Copyright (C) 2026 Paul Galbraith. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows replacement for the descriptor passing the vhost-user protocol relies on.
//!
//! On POSIX the protocol hands over the descriptors backing guest memory and the vring
//! kick/call/err notifications as `SCM_RIGHTS` ancillary data. Windows has no equivalent: the only
//! way to move a `HANDLE` between processes is `DuplicateHandle`, which requires knowing the peer's
//! process id up front, and vhost-user's backend is by design "whatever process connects to this
//! socket".
//!
//! The Windows transport therefore passes *names* of Win32 kernel objects instead of handles. The
//! object is created named in the `Local\` namespace by whichever side owns it, and wherever POSIX
//! attaches K descriptors to a message, Windows appends K fixed-size name records to that message's
//! payload:
//!
//! * each record is [`VHOST_USER_WIN32_NAME_SIZE`] bytes, NUL-terminated and NUL-padded;
//! * the message header's `size` field *includes* the trailer, so the records travel inside the
//!   normal payload of a plain byte-stream `AF_UNIX` socket and stay associated with their message
//!   without any extra framing;
//! * there is no count field on the wire — K is implied by the request, exactly as the
//!   `SCM_RIGHTS` descriptor count is on POSIX (see [`super::message::Req::win32_name_trailer`]).
//!
//! Names are opaque. The peer mints them and may change how it does so, so they are passed to
//! Win32 exactly as received and never parsed, validated, or re-encoded here.

use std::fs::File;
use std::os::windows::io::FromRawHandle;

use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Memory::{OpenFileMappingA, FILE_MAP_ALL_ACCESS};
use windows_sys::Win32::System::Threading::{OpenEventA, EVENT_MODIFY_STATE};

use super::{Error, Result};

/// Size of a single name record in a message trailer, matching `VHOST_USER_WIN32_NAME_SIZE` on the
/// frontend side.
pub const VHOST_USER_WIN32_NAME_SIZE: usize = 64;

/// The kind of Win32 kernel object a name record refers to.
///
/// The kind is a property of the request, not of the record, so it is decided by
/// [`super::message::Req::win32_name_trailer`] rather than read off the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Win32ObjectKind {
    /// A section object (file mapping) backing a guest memory region.
    Section,
    /// A manual-reset event object used for vring kick/call/err signalling.
    Event,
}

/// Split `count` trailing name records off `payload` and open the objects they name.
///
/// Returns the payload with the trailer removed — that is, the payload as a POSIX peer would have
/// sent it — together with the opened objects, in wire order.
pub fn take_named_objects(
    payload: &[u8],
    count: usize,
    kind: Win32ObjectKind,
) -> Result<(&[u8], Vec<File>)> {
    let trailer_len = count
        .checked_mul(VHOST_USER_WIN32_NAME_SIZE)
        .ok_or(Error::InvalidMessage)?;
    let base_len = payload
        .len()
        .checked_sub(trailer_len)
        .ok_or(Error::InvalidMessage)?;
    let (base, trailer) = payload.split_at(base_len);

    let mut files = Vec::with_capacity(count);
    for record in trailer.chunks_exact(VHOST_USER_WIN32_NAME_SIZE) {
        files.push(open_named_object(kind, record)?);
    }

    Ok((base, files))
}

/// Open the named object described by a single name record.
fn open_named_object(kind: Win32ObjectKind, record: &[u8]) -> Result<File> {
    // The record is NUL-terminated within its fixed size, so it is already a valid C string and can
    // be handed to Win32 as-is. A record with no NUL at all would run off the end of the buffer.
    if !record.contains(&0) {
        return Err(Error::InvalidMessage);
    }

    // SAFETY: `record` is NUL-terminated within its bounds as checked above, and stays borrowed for
    // the duration of the call.
    let handle = unsafe {
        match kind {
            Win32ObjectKind::Section => OpenFileMappingA(FILE_MAP_ALL_ACCESS, 0, record.as_ptr()),
            Win32ObjectKind::Event => {
                OpenEventA(SYNCHRONIZE | EVENT_MODIFY_STATE, 0, record.as_ptr())
            }
        }
    };
    if handle.is_null() {
        return Err(Error::Win32ObjectOpen(std::io::Error::last_os_error()));
    }

    // SAFETY: `handle` is a valid kernel object handle that we exclusively own.
    //
    // `File` is used purely as an owning handle wrapper: its `Drop` calls `CloseHandle`, which is
    // the correct disposal for section and event objects alike. Wrapping them keeps the request
    // handler API identical on both platforms — on POSIX an eventfd likewise reaches the handler as
    // a `File` — and callers immediately convert the handle into whatever they actually need.
    Ok(unsafe { File::from_raw_handle(handle as _) })
}

// Golden wire vectors for the record format, pinned through the production parser above. The
// sending side of the contract pins the identical vectors through its production formatter
// (QEMU's tests/unit/test-win32-shareable.c); a change that breaks either test breaks the
// other implementation.
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{CreateEventA, SetEvent, WaitForSingleObject};

    /// Vector 1: an ordinary name.
    const VECTOR_KICK_NAME: &str = "Local\\example-kick-0";

    /// Vector 2: the longest name that fits — 63 characters, leaving exactly one byte for the
    /// terminator.
    const VECTOR_MAX_NAME: &str =
        "Local\\012345678901234567890123456789012345678901234567890123456";

    /// The record layout under test: the name, its NUL terminator, and zero padding out to the
    /// fixed size.
    fn record(name: &str) -> [u8; VHOST_USER_WIN32_NAME_SIZE] {
        assert!(name.len() < VHOST_USER_WIN32_NAME_SIZE);
        let mut rec = [0u8; VHOST_USER_WIN32_NAME_SIZE];
        rec[..name.len()].copy_from_slice(name.as_bytes());
        rec
    }

    /// A manual-reset event created under `name`, so a record naming it can be opened.
    fn event_named(name: &str) -> HANDLE {
        let cname = std::ffi::CString::new(name).unwrap();
        // SAFETY: `cname` is a valid NUL-terminated string for the duration of the call.
        let h = unsafe { CreateEventA(std::ptr::null(), 1, 0, cname.as_ptr().cast()) };
        assert!(!h.is_null());
        h
    }

    fn is_signaled(f: &File) -> bool {
        // SAFETY: the handle is open for the lifetime of `f`.
        match unsafe { WaitForSingleObject(f.as_raw_handle() as HANDLE, 0) } {
            WAIT_OBJECT_0 => true,
            WAIT_TIMEOUT => false,
            other => panic!("unexpected wait result {other:#x}"),
        }
    }

    #[test]
    fn a_record_is_the_name_nul_padded() {
        let created = event_named(VECTOR_KICK_NAME);
        let mut payload = b"base payload".to_vec();
        payload.extend_from_slice(&record(VECTOR_KICK_NAME));

        let (base, objects) = take_named_objects(&payload, 1, Win32ObjectKind::Event).unwrap();
        assert_eq!(base, b"base payload");
        assert_eq!(objects.len(), 1);

        // The opened object is the created one: signaling the original shows up through it.
        assert!(!is_signaled(&objects[0]));
        // SAFETY: `created` is a valid event handle.
        unsafe { SetEvent(created) };
        assert!(is_signaled(&objects[0]));
    }

    #[test]
    fn the_longest_name_exactly_fits() {
        assert_eq!(VECTOR_MAX_NAME.len(), VHOST_USER_WIN32_NAME_SIZE - 1);
        let _created = event_named(VECTOR_MAX_NAME);
        let payload = record(VECTOR_MAX_NAME);

        let (base, objects) = take_named_objects(&payload, 1, Win32ObjectKind::Event).unwrap();
        assert!(base.is_empty());
        assert_eq!(objects.len(), 1);
    }

    #[test]
    fn a_record_without_a_terminator_is_refused() {
        // The sender cannot produce this (its formatter requires room for the NUL); a peer that
        // does is speaking something other than the contract.
        let payload = [b'X'; VHOST_USER_WIN32_NAME_SIZE];
        assert!(matches!(
            take_named_objects(&payload, 1, Win32ObjectKind::Event),
            Err(Error::InvalidMessage)
        ));
    }

    #[test]
    fn a_payload_shorter_than_its_trailer_is_refused() {
        let payload = [0u8; VHOST_USER_WIN32_NAME_SIZE - 1];
        assert!(matches!(
            take_named_objects(&payload, 1, Win32ObjectKind::Event),
            Err(Error::InvalidMessage)
        ));
    }

    #[test]
    fn a_name_no_object_carries_is_refused() {
        let payload = record("Local\\example-does-not-exist");
        assert!(matches!(
            take_named_objects(&payload, 1, Win32ObjectKind::Event),
            Err(Error::Win32ObjectOpen(_))
        ));
    }

    #[test]
    fn a_trailer_splits_records_in_order() {
        let first = event_named("Local\\example-ram-0");
        let _second = event_named("Local\\example-ram-1");

        let mut payload = Vec::new();
        payload.extend_from_slice(&record("Local\\example-ram-0"));
        payload.extend_from_slice(&record("Local\\example-ram-1"));

        let (base, objects) = take_named_objects(&payload, 2, Win32ObjectKind::Event).unwrap();
        assert!(base.is_empty());
        assert_eq!(objects.len(), 2);

        // Signal only the first-named object: order is observable, not assumed.
        // SAFETY: `first` is a valid event handle.
        unsafe { SetEvent(first) };
        assert!(is_signaled(&objects[0]));
        assert!(!is_signaled(&objects[1]));
    }
}
