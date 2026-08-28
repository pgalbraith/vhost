// Copyright (C) 2026 Paul Galbraith. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows replacement for `SCM_RIGHTS` descriptor passing.
//!
//! POSIX hands over guest-memory descriptors and vring kick/call/err notifications as `SCM_RIGHTS`
//! ancillary data. Windows sockets carry no ancillary data at all, so the transport moves kernel
//! objects with `DuplicateHandle` instead: before sending, the frontend duplicates each object into
//! *this* process and puts the resulting handle value in the message.
//!
//! Wherever POSIX attaches K descriptors to a message, Windows appends K handle records to the
//! payload:
//!
//! * each record is [`VHOST_USER_WIN32_HANDLE_RECORD_SIZE`] bytes, a handle value already valid
//!   here;
//! * the header's `size` field includes the trailer, so message and records arrive together with no
//!   extra framing;
//! * there's no count field on the wire — K is implied by the request, same as the `SCM_RIGHTS`
//!   descriptor count on POSIX (see [`super::message::Req::win32_handle_trailer`]).
//!
//! This side owns each handle it receives and closes it when done, exactly as a POSIX backend
//! closes a received descriptor. Nothing else is required of a backend: it never opens, names, or
//! duplicates anything, and the frontend needs no cooperation from it to hand over an object.
//!
//! See "Windows platform support" in QEMU's `docs/interop/vhost-user.rst` for the full binding.

use std::fs::File;
use std::os::windows::io::FromRawHandle;

use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE};

use super::{Error, Result};

/// Size of a single handle record in a message trailer, matching
/// `VHOST_USER_WIN32_HANDLE_RECORD_SIZE` on the frontend side.
pub const VHOST_USER_WIN32_HANDLE_RECORD_SIZE: usize = 8;

/// Split `count` trailing handle records off `payload` and adopt the objects they name.
///
/// Returns the payload with the trailer removed — that is, the payload as a POSIX peer would have
/// sent it — together with the adopted objects, in wire order.
pub fn take_handles(payload: &[u8], count: usize) -> Result<(&[u8], Vec<File>)> {
    let trailer_len = count
        .checked_mul(VHOST_USER_WIN32_HANDLE_RECORD_SIZE)
        .ok_or(Error::InvalidMessage)?;
    let base_len = payload
        .len()
        .checked_sub(trailer_len)
        .ok_or(Error::InvalidMessage)?;
    let (base, trailer) = payload.split_at(base_len);

    let mut files = Vec::with_capacity(count);
    for record in trailer.chunks_exact(VHOST_USER_WIN32_HANDLE_RECORD_SIZE) {
        files.push(adopt_handle(record)?);
    }

    Ok((base, files))
}

/// Adopt the object described by a single handle record.
fn adopt_handle(record: &[u8]) -> Result<File> {
    // Native byte order, like every other field of the protocol.
    let value = u64::from_le_bytes(record.try_into().map_err(|_| Error::InvalidMessage)?);
    let handle = value as usize as HANDLE;

    // A record naming something that is not a live handle here means the peer is not speaking this
    // binding: a duplicate the frontend made is valid by construction. Refusing beats adopting a
    // value that may alias an unrelated handle of ours, which we would later close. A handle of the
    // wrong *kind* is not detected here; it fails when the object is used, as a wrong-type
    // descriptor does on POSIX.
    let mut flags = 0u32;
    // SAFETY: querying an arbitrary handle value is safe; the call reports validity rather than
    // trapping on a bad one.
    if handle.is_null() || unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
        return Err(Error::Win32InvalidHandle(std::io::Error::last_os_error()));
    }

    // SAFETY: `handle` is a valid kernel object handle, duplicated into this process by the peer
    // and owned by us from here on.
    //
    // `File` is just an owning wrapper — `Drop` calls `CloseHandle`, correct for both section and
    // event objects — kept so the handler API matches POSIX, where an eventfd also arrives as a
    // `File`. Callers convert to whatever they actually need.
    Ok(unsafe { File::from_raw_handle(handle as _) })
}

// The record format is the cross-implementation surface: QEMU formats these bytes and this parser
// reads them. The vectors below pin the layout through the production parser; QEMU pins the
// duplication primitive on its side (tests/unit/test-win32-shareable.c).
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{
        DuplicateHandle, DUPLICATE_SAME_ACCESS, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventA, GetCurrentProcess, SetEvent, WaitForSingleObject,
    };

    /// An auto-reset event (the kick contract's mode), unnamed as the binding requires.
    fn event() -> HANDLE {
        // SAFETY: all arguments are simple values; the result is checked.
        let h = unsafe { CreateEventA(std::ptr::null(), 0, 0, std::ptr::null()) };
        assert!(!h.is_null());
        h
    }

    /// What the frontend does before sending: duplicate into the peer — here, ourselves — and put
    /// the resulting value on the wire.
    fn record(local: HANDLE) -> [u8; VHOST_USER_WIN32_HANDLE_RECORD_SIZE] {
        let mut dup: HANDLE = std::ptr::null_mut();
        // SAFETY: both process handles are the current-process pseudo handle, `local` is live, and
        // `dup` is a valid out-pointer.
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                local,
                GetCurrentProcess(),
                &mut dup,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        assert!(ok != 0, "{}", std::io::Error::last_os_error());
        (dup as usize as u64).to_le_bytes()
    }

    /// NB: on an auto-reset event a `true` answer consumes the signal;
    /// each test checks a signaled event at most once.
    fn is_signaled(f: &File) -> bool {
        // SAFETY: the handle is open for the lifetime of `f`.
        match unsafe { WaitForSingleObject(f.as_raw_handle() as HANDLE, 0) } {
            WAIT_OBJECT_0 => true,
            WAIT_TIMEOUT => false,
            other => panic!("unexpected wait result {other:#x}"),
        }
    }

    #[test]
    fn a_record_is_a_handle_value() {
        let created = event();
        let mut payload = b"base payload".to_vec();
        payload.extend_from_slice(&record(created));

        let (base, objects) = take_handles(&payload, 1).unwrap();
        assert_eq!(base, b"base payload");
        assert_eq!(objects.len(), 1);

        // The adopted object is the created one: signaling the original shows up through it.
        assert!(!is_signaled(&objects[0]));
        // SAFETY: `created` is a valid event handle.
        unsafe { SetEvent(created) };
        assert!(is_signaled(&objects[0]));
    }

    #[test]
    fn a_record_that_is_not_a_handle_is_refused() {
        // The frontend cannot produce this; a peer that does is speaking something else.
        let payload = 0xdead_beef_u64.to_le_bytes();
        assert!(matches!(
            take_handles(&payload, 1),
            Err(Error::Win32InvalidHandle(_))
        ));
    }

    #[test]
    fn a_null_handle_is_refused() {
        let payload = 0u64.to_le_bytes();
        assert!(matches!(
            take_handles(&payload, 1),
            Err(Error::Win32InvalidHandle(_))
        ));
    }

    #[test]
    fn a_payload_shorter_than_its_trailer_is_refused() {
        let payload = [0u8; VHOST_USER_WIN32_HANDLE_RECORD_SIZE - 1];
        assert!(matches!(take_handles(&payload, 1), Err(Error::InvalidMessage)));
    }

    #[test]
    fn a_trailer_splits_records_in_order() {
        let first = event();
        let second = event();

        let mut payload = Vec::new();
        payload.extend_from_slice(&record(first));
        payload.extend_from_slice(&record(second));

        let (base, objects) = take_handles(&payload, 2).unwrap();
        assert!(base.is_empty());
        assert_eq!(objects.len(), 2);

        // Signal only the first object: order is observable, not assumed.
        // SAFETY: `first` is a valid event handle.
        unsafe { SetEvent(first) };
        assert!(is_signaled(&objects[0]));
        assert!(!is_signaled(&objects[1]));
    }

    #[test]
    fn adopting_takes_ownership() {
        let created = event();
        let payload = record(created);

        let (_, objects) = take_handles(&payload, 1).unwrap();
        let adopted = objects[0].as_raw_handle() as HANDLE;

        // Dropping the wrapper closes the duplicate, and only the duplicate: the frontend keeps its
        // own handle, as an SCM_RIGHTS sender keeps its descriptor.
        drop(objects);
        let mut flags = 0u32;
        // SAFETY: querying a stale handle value reports invalidity rather than trapping.
        assert_eq!(unsafe { GetHandleInformation(adopted, &mut flags) }, 0);
        // SAFETY: `created` is still ours.
        assert_ne!(unsafe { GetHandleInformation(created, &mut flags) }, 0);
    }
}
