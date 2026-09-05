// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! The completion-port vring loop: the Windows counterpart of the epoll loop
//! in `event_loop.rs`.

use std::io;
use std::marker::PhantomData;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use std::sync::Arc;

use vmm_sys_util::completion::{Completion, Port};
use vmm_sys_util::event::EventConsumer;

use super::completion_backend::VhostUserCompletionBackend;
use super::vring::VringT;
use super::worker::VringWorker;

/// One worker thread's loop over an I/O completion port.
///
/// Kicks reach the port through the registered wait `Port::register` sets
/// up: each time the kick event is set, one packet arrives under the vring's
/// index within this worker, and the wait itself consumed the signal, so
/// there is nothing to read before calling the device. The loop stops on a
/// packet posted under `num_queues()`, the key the epoll loop uses for its
/// exit event; there is no event object for it. Everything else the port
/// delivers goes to the device's `handle_completion`.
///
/// The device is handed the port (`Arc<Port>`) through `attach` before the
/// loop starts, and [`port`](Self::port) hands it to anyone else; the port
/// lives as long as the last holder. Dropping it cancels and drains every
/// outstanding operation, which is why a device that submits I/O should
/// let go of its `Arc` only when it has no more submissions to make.
pub struct VringCompletionHandler<T: VhostUserCompletionBackend> {
    port: Arc<Port>,
    backend: T,
    vrings: Vec<T::Vring>,
    thread_id: usize,
    /// `num_queues()`: above every kick index of every worker, below every
    /// key the device may use.
    exit_key: usize,
    phantom: PhantomData<T::Bitmap>,
}

impl<T: VhostUserCompletionBackend> VringCompletionHandler<T> {
    /// A loop for worker thread `thread_id` over a fresh port, with the
    /// device attached to it.
    pub(crate) fn new(backend: T, vrings: Vec<T::Vring>, thread_id: usize) -> io::Result<Self> {
        let port = Arc::new(Port::new()?);
        let exit_key = backend.num_queues();
        backend.attach(thread_id, port.clone())?;
        Ok(VringCompletionHandler {
            port,
            backend,
            vrings,
            thread_id,
            exit_key,
            phantom: PhantomData,
        })
    }

    /// The port this worker waits on.
    pub fn port(&self) -> Arc<Port> {
        self.port.clone()
    }
}

/// A kick as `Port` takes it: the event handle, borrowed for the call.
fn kick_handle(kick: &EventConsumer) -> BorrowedHandle<'_> {
    // SAFETY: the handle is open for as long as `kick` is, which covers the
    // returned borrow.
    unsafe { BorrowedHandle::borrow_raw(kick.as_raw_handle()) }
}

impl<T> VringWorker for VringCompletionHandler<T>
where
    T: VhostUserCompletionBackend + 'static,
    T::Vring: Send + Sync,
    T::Bitmap: Send + Sync,
{
    fn register_kick(&self, kick: &EventConsumer, index: u64) -> io::Result<()> {
        self.port.register(kick_handle(kick), index as usize)
    }

    fn unregister_kick(&self, kick: &EventConsumer, _index: u64) -> io::Result<()> {
        self.port.unregister(kick_handle(kick))
    }

    fn run(&self) -> io::Result<()> {
        let mut completions = Vec::new();
        loop {
            self.port.wait(None, &mut completions)?;
            for completion in completions.drain(..) {
                match completion {
                    Completion::Signal { key } if key < self.vrings.len() => {
                        // The wait that queued this packet reset the event, so the kick is
                        // already consumed; `read_kick` would have nothing to do. What the
                        // epoll loop takes from `read_kick` is the enabled flag, checked here
                        // directly: a disabled vring is not processed.
                        if !self.vrings[key].get_ref().is_enabled() {
                            continue;
                        }
                        self.backend
                            .handle_kick(key as u16, &self.vrings, self.thread_id)?;
                    }
                    Completion::Posted { key, .. } if key == self.exit_key => return Ok(()),
                    other => self
                        .backend
                        .handle_completion(other, &self.vrings, self.thread_id)?,
                }
            }
        }
    }

    fn send_exit_event(&self) {
        // A failed post means the port is gone, and with it the loop.
        let _ = self.port.post(self.exit_key, 0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::super::completion_backend::tests::MockCompletionBackend;
    use super::super::vring::VringRwLock;
    use super::*;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};
    use vmm_sys_util::event::{new_event_consumer_and_notifier, EventFlag};

    type Backend = Arc<Mutex<MockCompletionBackend>>;

    /// One worker over one vring, with the device and vring handed back for the test to drive.
    fn handler() -> (Backend, VringCompletionHandler<Backend>, VringRwLock) {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        let backend = Arc::new(Mutex::new(MockCompletionBackend::new()));
        let handler =
            VringCompletionHandler::new(backend.clone(), vec![vring.clone()], 0x1).unwrap();
        (backend, handler, vring)
    }

    #[test]
    fn test_vring_completion_handler() {
        let (backend, handler, _vring) = handler();

        // The device was attached to this worker's port before anything ran.
        let ports = backend.lock().unwrap().ports().to_vec();
        assert_eq!(ports.len(), 1);
        assert_eq!(
            ports[0].as_raw_handle(),
            handler.port().as_raw_handle(),
            "attach was given a different port from the one the loop waits on"
        );

        let (consumer, _notifier) = new_event_consumer_and_notifier(EventFlag::empty()).unwrap();
        handler.register_kick(&consumer, 0).unwrap();
        // Register an already registered kick.
        assert_eq!(
            handler.register_kick(&consumer, 0).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        handler.unregister_kick(&consumer, 0).unwrap();
        // Unregister an already unregistered kick.
        assert_eq!(
            handler.unregister_kick(&consumer, 0).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        // An exit posted before `run` is picked up by it.
        handler.send_exit_event();
        handler.run().unwrap();
    }

    #[test]
    fn test_dispatch_by_key() {
        let (backend, handler, vring) = handler();
        let handler = Arc::new(handler);
        let (kick, notifier) = new_event_consumer_and_notifier(EventFlag::empty()).unwrap();
        handler.register_kick(&kick, 0).unwrap();

        let worker = {
            let handler = handler.clone();
            thread::spawn(move || handler.run())
        };

        // A kick on a vring that is not enabled is dropped, not delivered.
        notifier.notify().unwrap();
        thread::sleep(Duration::from_millis(200));
        assert_eq!(backend.lock().unwrap().events(), 0);

        vring.set_enabled(true);
        notifier.notify().unwrap();
        thread::sleep(Duration::from_millis(200));
        assert_eq!(backend.lock().unwrap().events(), 1);

        // A packet under a device key goes to handle_completion, not the kick path, and
        // nothing about it is mistaken for the exit.
        let port = handler.port();
        port.post(backend.num_queues() + 1, 0, 0).unwrap();
        thread::sleep(Duration::from_millis(200));
        assert_eq!(backend.lock().unwrap().completions(), 1);
        assert_eq!(backend.lock().unwrap().events(), 1);

        handler.send_exit_event();
        worker.join().unwrap().unwrap();
        handler.unregister_kick(&kick, 0).unwrap();
    }
}
