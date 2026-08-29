// Copyright (C) 2026 Paul Galbraith. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows replacement for `SCM_RIGHTS` descriptor passing.
//!
//! POSIX hands over guest-memory descriptors and vring kick/call/err notifications as `SCM_RIGHTS`
//! ancillary data. Windows sockets carry no ancillary data at all, so the transport moves kernel
//! objects with `DuplicateHandle` instead. Every handle value on the wire is relative to the
//! *backend* process, in both directions:
//!
//! * The frontend duplicates each object it sends into the backend process
//!   ([`duplicate_into_peer`]) and puts the resulting handle values in the message. The backend
//!   adopts them as they are.
//! * An object the backend sends is one of the backend's own handles; the frontend pulls it over
//!   with a `DUPLICATE_CLOSE_SOURCE` duplication, which removes the backend's copy in the same
//!   step.
//!
//! [`take_handles`] covers both receive directions; only the frontend needs a handle to the peer
//! process. Nothing is required of a backend beyond using the handles it receives: it never opens,
//! names, or duplicates anything, and the frontend needs no cooperation from it to hand over an
//! object.
//!
//! Wherever POSIX attaches K descriptors to a message, Windows appends K handle records to the
//! payload:
//!
//! * each record is [`VHOST_USER_WIN32_HANDLE_RECORD_SIZE`] bytes;
//! * the header's `size` field includes the trailer, so message and records arrive together with no
//!   extra framing;
//! * there's no count field on the wire — K is implied by the request, same as the `SCM_RIGHTS`
//!   descriptor count on POSIX (see [`super::message::Req::win32_handle_trailer`]).
//!
//! This side owns each handle it receives and closes it when done, exactly as a POSIX peer closes
//! a received descriptor.
//!
//! See "Windows platform support" in QEMU's `docs/interop/vhost-user.rst` for the full binding.

use std::fs::File;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle};

use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetHandleInformation, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, HANDLE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::connection::RawDescriptor;
use super::{Error, Result};

/// Size of a single handle record in a message trailer, matching
/// `VHOST_USER_WIN32_HANDLE_RECORD_SIZE` on the frontend side.
pub const VHOST_USER_WIN32_HANDLE_RECORD_SIZE: usize = 8;

/// Split `count` trailing handle records off `payload` and take ownership of the objects they
/// name.
///
/// `peer` decides how a record becomes a local handle. `None` is the backend side: the frontend
/// already duplicated each object here, so the record is adopted as it is. `Some` is the frontend
/// side: the record names one of the backend's handles, pulled over with a
/// `DUPLICATE_CLOSE_SOURCE` duplication that removes the backend's copy in the same step.
///
/// Returns the payload with the trailer removed — that is, the payload as a POSIX peer would have
/// sent it — together with the owned objects, in wire order.
pub fn take_handles<'a>(
    peer: Option<BorrowedHandle<'_>>,
    payload: &'a [u8],
    count: usize,
) -> Result<(&'a [u8], Vec<File>)> {
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
        files.push(match peer {
            None => adopt_handle(record)?,
            Some(peer) => pull_handle(peer, record)?,
        });
    }

    Ok((base, files))
}

/// Duplicate `handles` into the peer process and return the trailer records naming the
/// duplicates, in wire order.
///
/// All or nothing: if any duplication fails, the duplicates already made are closed again in the
/// peer, so a failed send leaves the peer exactly as it was — the property an `SCM_RIGHTS` sender
/// gets from the kernel for free.
pub fn duplicate_into_peer(peer: BorrowedHandle<'_>, handles: &[RawDescriptor]) -> Result<Vec<u8>> {
    let mut trailer = Vec::with_capacity(handles.len() * VHOST_USER_WIN32_HANDLE_RECORD_SIZE);
    for &handle in handles {
        let mut dup: HANDLE = std::ptr::null_mut();
        // SAFETY: the source process is this one, `peer` is a live process handle for the
        // duration of the call, and `dup` is a valid out-pointer. A dead or invalid `handle`
        // makes the call fail, checked below. `bInheritHandle` is 0: the binding requires
        // duplicates to be non-inheritable.
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle as HANDLE,
                peer.as_raw_handle() as HANDLE,
                &mut dup,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            close_in_peer(peer, &trailer);
            return Err(Error::Win32HandleTransfer(err));
        }
        trailer.extend_from_slice(&(dup as usize as u64).to_le_bytes());
    }
    Ok(trailer)
}

/// Close the handles named by `trailer` in the peer process.
///
/// For unwinding a send that failed after its handles were already duplicated over: the peer was
/// never told about them, so leaving them open would hold the objects alive for the peer's whole
/// lifetime. Best effort — a handle that cannot be closed any more needs nothing done.
pub fn close_in_peer(peer: BorrowedHandle<'_>, trailer: &[u8]) {
    for record in trailer.chunks_exact(VHOST_USER_WIN32_HANDLE_RECORD_SIZE) {
        let value = u64::from_le_bytes(record.try_into().unwrap());
        // SAFETY: closing a handle in the source process via DUPLICATE_CLOSE_SOURCE with no
        // target process or out-pointer is the documented remote-close form of DuplicateHandle;
        // it dereferences nothing of ours.
        unsafe {
            DuplicateHandle(
                peer.as_raw_handle() as HANDLE,
                value as usize as HANDLE,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                0,
                DUPLICATE_CLOSE_SOURCE,
            );
        }
    }
}

/// Take the object a single record names out of the peer process.
fn pull_handle(peer: BorrowedHandle<'_>, record: &[u8]) -> Result<File> {
    // Native byte order, like every other field of the protocol.
    let value = u64::from_le_bytes(record.try_into().map_err(|_| Error::InvalidMessage)?);

    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: `peer` is a live process handle for the duration of the call and `dup` is a valid
    // out-pointer; a record that doesn't name a live handle in the peer makes the call fail,
    // checked below. DUPLICATE_CLOSE_SOURCE removes the peer's copy in the same step — the peer
    // gave the handle away and must not be left holding a value it might mistake for its own.
    let ok = unsafe {
        DuplicateHandle(
            peer.as_raw_handle() as HANDLE,
            value as usize as HANDLE,
            GetCurrentProcess(),
            &mut dup,
            0,
            0,
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
        )
    };
    if ok == 0 {
        return Err(Error::Win32InvalidHandle(std::io::Error::last_os_error()));
    }

    // SAFETY: `dup` is a valid handle owned by this process from here on; see `adopt_handle` for
    // why `File` is the wrapper.
    Ok(unsafe { File::from_raw_handle(dup as _) })
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

/// A real (non-pseudo) handle to this process, for tests that play both ends of a connection in
/// one process: duplicating into or out of it exercises the same calls as a real peer.
#[cfg(test)]
pub(crate) fn current_process() -> std::os::windows::io::OwnedHandle {
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: all three process arguments are the current-process pseudo handle and `handle` is a
    // valid out-pointer; the result is checked.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            GetCurrentProcess(),
            &mut handle,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    assert!(ok != 0, "{}", std::io::Error::last_os_error());
    // SAFETY: `handle` is a live handle this process owns from here on.
    unsafe { std::os::windows::io::FromRawHandle::from_raw_handle(handle as _) }
}

// The record format is the cross-implementation surface: QEMU formats these bytes and this parser
// reads them. The vectors below pin the layout through the production parser; QEMU pins the
// duplication primitive on its side (tests/unit/test-win32-shareable.c).
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::{AsHandle, AsRawHandle};
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{CreateEventA, SetEvent, WaitForSingleObject};

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

        let (base, objects) = take_handles(None, &payload, 1).unwrap();
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
            take_handles(None, &payload, 1),
            Err(Error::Win32InvalidHandle(_))
        ));
    }

    #[test]
    fn a_null_handle_is_refused() {
        let payload = 0u64.to_le_bytes();
        assert!(matches!(
            take_handles(None, &payload, 1),
            Err(Error::Win32InvalidHandle(_))
        ));
    }

    #[test]
    fn a_payload_shorter_than_its_trailer_is_refused() {
        let payload = [0u8; VHOST_USER_WIN32_HANDLE_RECORD_SIZE - 1];
        assert!(matches!(
            take_handles(None, &payload, 1),
            Err(Error::InvalidMessage)
        ));
    }

    #[test]
    fn a_trailer_splits_records_in_order() {
        let first = event();
        let second = event();

        let mut payload = Vec::new();
        payload.extend_from_slice(&record(first));
        payload.extend_from_slice(&record(second));

        let (base, objects) = take_handles(None, &payload, 2).unwrap();
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

        let (_, objects) = take_handles(None, &payload, 1).unwrap();
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

    #[test]
    fn duplicating_into_the_peer_makes_live_records() {
        let created = event();
        let peer = current_process();

        let trailer = duplicate_into_peer(peer.as_handle(), &[created as _]).unwrap();
        assert_eq!(trailer.len(), VHOST_USER_WIN32_HANDLE_RECORD_SIZE);

        // The record is a live handle in the peer (this process), distinct from the original,
        // and reaches the same object.
        let (_, objects) = take_handles(None, &trailer, 1).unwrap();
        assert_ne!(objects[0].as_raw_handle() as HANDLE, created);
        // SAFETY: `created` is a valid event handle.
        unsafe { SetEvent(created) };
        assert!(is_signaled(&objects[0]));
    }

    #[test]
    fn duplicating_a_bad_handle_is_reported() {
        let first = event();
        let peer = current_process();

        // The second handle is junk, so the whole transfer fails; `duplicate_into_peer` unwinds
        // the duplicate of `first` through `close_in_peer`, whose own test is below. The original
        // stays ours, as always.
        let bad = 0xdead_beef_usize as RawDescriptor;
        assert!(matches!(
            duplicate_into_peer(peer.as_handle(), &[first as _, bad]),
            Err(Error::Win32HandleTransfer(_))
        ));
        let mut flags = 0u32;
        // SAFETY: `first` is a live handle we own.
        assert_ne!(unsafe { GetHandleInformation(first, &mut flags) }, 0);
    }

    #[test]
    fn closing_in_the_peer_closes_exactly_the_records() {
        let created = event();
        let peer = current_process();
        let trailer = duplicate_into_peer(peer.as_handle(), &[created as _]).unwrap();
        let duplicate = u64::from_le_bytes(trailer[..8].try_into().unwrap()) as usize as HANDLE;

        let mut flags = 0u32;
        // SAFETY: the duplicate lives in the peer — this process — until closed there.
        assert_ne!(unsafe { GetHandleInformation(duplicate, &mut flags) }, 0);

        close_in_peer(peer.as_handle(), &trailer);

        // SAFETY: querying a stale handle value reports invalidity rather than trapping.
        assert_eq!(unsafe { GetHandleInformation(duplicate, &mut flags) }, 0);
        // SAFETY: `created` is a live handle we own; only the duplicate was closed.
        assert_ne!(unsafe { GetHandleInformation(created, &mut flags) }, 0);
    }

    #[test]
    fn pulling_takes_the_object() {
        let created = event();
        let peer = current_process();
        // The record names a second handle to the object — the one the backend gives away.
        // `created` stays ours, standing in for the handle a real backend keeps for its own use.
        let payload = record(created);

        let (_, objects) = take_handles(Some(peer.as_handle()), &payload, 1).unwrap();

        // The pulled handle reaches the object: signaling our own handle shows up through it.
        // That the pull also closed the given-away source handle can't be asserted here: with
        // both "processes" being this one, the kernel typically hands the freed slot straight
        // back as the pulled duplicate, so the source value is live again by design.
        assert!(!is_signaled(&objects[0]));
        // SAFETY: `created` is a valid event handle.
        unsafe { SetEvent(created) };
        assert!(is_signaled(&objects[0]));
    }

    #[test]
    fn pulling_a_dead_record_is_refused() {
        let peer = current_process();
        let payload = 0xdead_beef_u64.to_le_bytes();
        assert!(matches!(
            take_handles(Some(peer.as_handle()), &payload, 1),
            Err(Error::Win32InvalidHandle(_))
        ));
    }
}
