// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! The loop a vring worker thread runs, seen from the control channel.

use std::io;

use vmm_sys_util::event::EventConsumer;

/// One worker thread's loop: what the control channel needs from it, and
/// nothing about how it waits.
///
/// `VhostUserHandler` creates one of these per entry of the device's
/// `queues_per_thread`, spawns a thread running [`run`](Self::run), and
/// registers or unregisters each vring's kick as the front-end enables,
/// disables, starts or stops the ring. Which primitive the loop waits on is
/// its own business: the epoll loop (`VringEpollHandler`) registers the
/// kick with an epoll instance, and a completion-port loop bridges it in
/// through a registered wait. The device sees the same kicks either way.
///
/// Indexes are per worker, not per device: a kick registered under `index`
/// is the `index`th vring of *this* worker's vrings, which is how the loop
/// finds the vring to hand to the device when the kick fires.
pub trait VringWorker: Send + Sync + 'static {
    /// Start delivering `kick` as vring `index` of this worker.
    ///
    /// Registering a kick that is already registered is
    /// `io::ErrorKind::AlreadyExists`, which the control channel ignores:
    /// the front-end may enable a ring that is already enabled.
    fn register_kick(&self, kick: &EventConsumer, index: u64) -> io::Result<()>;

    /// Stop delivering `kick`. A kick that fires after this returns is
    /// dropped. Must be called before the kick's handle is closed.
    fn unregister_kick(&self, kick: &EventConsumer, index: u64) -> io::Result<()>;

    /// Run the loop on the current thread until
    /// [`send_exit_event`](Self::send_exit_event) is called.
    fn run(&self) -> io::Result<()>;

    /// Ask the loop to return from [`run`](Self::run). Safe to call more
    /// than once, and before or after the loop has started.
    fn send_exit_event(&self);
}
