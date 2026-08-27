// Copyright (C) 2026 Paul Galbraith. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows replacement for `SCM_RIGHTS` descriptor passing.
//!
//! POSIX hands over guest-memory descriptors and vring kick/call/err notifications as `SCM_RIGHTS`
//! ancillary data. Windows has no equivalent: moving a `HANDLE` between processes needs
//! `DuplicateHandle`, which requires the peer's process id up front, but vhost-user's backend
//! accepts any process that connects to the socket.
//!
//! So the Windows transport passes *names* of Win32 kernel objects instead of handles. The owning
//! side creates the object named in the `Local\` namespace; wherever POSIX attaches K descriptors
//! to a message, Windows appends K fixed-size name records to the payload:
//!
//! * each record is [`VHOST_USER_WIN32_NAME_SIZE`] bytes, NUL-terminated and NUL-padded;
//! * the header's `size` field includes the trailer, so records travel inside the normal payload
//!   with no extra framing;
//! * there's no count field on the wire — K is implied by the request, same as the `SCM_RIGHTS`
//!   descriptor count on POSIX (see [`super::message::Req::win32_name_trailer`]).
//!
//! Names are opaque: the peer mints them and may change how, so they're passed to Win32 exactly as
//! received, never parsed, validated, or re-encoded here.

use std::fs::File;
use std::os::windows::io::FromRawHandle;

use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Memory::{OpenFileMappingA, FILE_MAP_READ, FILE_MAP_WRITE};
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
    /// An event object used for vring kick/call/err signalling. Reset mode
    /// follows the waiter (see the interop spec): kick events are
    /// auto-reset and consumed by this side's waits; call/err events are
    /// manual-reset and only ever signalled from this side.
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
    // Already NUL-terminated within its bounds, so it's a valid C string as-is; without a NUL
    // it'd run off the end of the buffer.
    if !record.contains(&0) {
        return Err(Error::InvalidMessage);
    }

    // SAFETY: `record` is NUL-terminated within its bounds as checked above, and stays borrowed for
    // the duration of the call.
    let handle = unsafe {
        match kind {
            Win32ObjectKind::Section => {
                // Read/write mapping access only: everything a guest-memory
                // view needs, and nothing a compromised back-end could use
                // to extend the section or rewrite its security descriptor
                // (no SECTION_EXTEND_SIZE, no WRITE_DAC).
                OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, 0, record.as_ptr())
            }
            Win32ObjectKind::Event => {
                // EVENT_QUERY_STATE (not exposed outside windows-sys's Wdk
                // tree) lets vmm-sys-util's debug-build Epoll guard verify
                // the event is auto-reset via NtQueryEvent; without it the
                // guard panics on an unverifiable kick. A frontend that
                // ever tightens its event DACL must keep granting it.
                const EVENT_QUERY_STATE: u32 = 0x0001;
                OpenEventA(
                    SYNCHRONIZE | EVENT_MODIFY_STATE | EVENT_QUERY_STATE,
                    0,
                    record.as_ptr(),
                )
            }
        }
    };
    if handle.is_null() {
        return Err(Error::Win32ObjectOpen(std::io::Error::last_os_error()));
    }

    // SAFETY: `handle` is a valid kernel object handle we exclusively own.
    //
    // `File` is just an owning wrapper here — `Drop` calls `CloseHandle`, correct for both section
    // and event objects — kept so the handler API matches POSIX, where an eventfd also arrives as
    // a `File`. Callers convert to whatever they actually need.
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

    /// An auto-reset event created under `name` (the kick contract's mode),
    /// so a record naming it can be opened.
    fn event_named(name: &str) -> HANDLE {
        let cname = std::ffi::CString::new(name).unwrap();
        // SAFETY: `cname` is a valid NUL-terminated string for the duration of the call.
        let h = unsafe { CreateEventA(std::ptr::null(), 0, 0, cname.as_ptr().cast()) };
        assert!(!h.is_null());
        h
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
