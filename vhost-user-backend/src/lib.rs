// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud Computing. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A simple framework to run a vhost-user backend service.

#[macro_use]
extern crate log;

use std::fmt::{Display, Formatter};
use std::net::Shutdown;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
#[cfg(windows)]
use uds_windows::UnixStream;

use vhost::vhost_user::{BackendListener, BackendReqHandler, Error as VhostUserError, Listener};
use vm_memory::mmap::NewBitmap;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
#[cfg(all(windows, feature = "completion"))]
use vmm_sys_util::completion::Port;

use self::handler::VhostUserHandler;

mod backend;
pub use self::backend::{VhostUserBackend, VhostUserBackendMut};

#[cfg(all(windows, feature = "completion"))]
mod completion_backend;
#[cfg(all(windows, feature = "completion"))]
pub use self::completion_backend::{VhostUserCompletionBackend, VhostUserCompletionBackendMut};

#[cfg(all(windows, feature = "completion"))]
mod completion_loop;
#[cfg(all(windows, feature = "completion"))]
pub use self::completion_loop::VringCompletionHandler;

mod event_loop;
pub use self::event_loop::VringEpollHandler;

// Public as a module, not re-exported at the root: a glob import of this crate must not bring
// the trait's methods into scope beside `VhostUserBackend`'s, which spell the same.
pub mod protocol;
use self::protocol::ProtocolBackend;

mod handler;
pub use self::handler::VhostUserHandlerError;

pub mod bitmap;
use crate::bitmap::BitmapReplace;

mod vring;
pub use self::vring::{
    VringMutex, VringRwLock, VringState, VringStateGuard, VringStateMutGuard, VringT,
};

mod worker;
pub use self::worker::VringWorker;

// Due to the way `xen` handles memory mappings we can not combine it with
// `postcopy` feature which relies on persistent memory mappings. Thus we
// disallow enabling both features at the same time.
#[cfg(all(
    not(RUSTDOC_disable_feature_compat_errors),
    not(doc),
    feature = "postcopy",
    feature = "xen"
))]
compile_error!("Both `postcopy` and `xen` features can not be enabled at the same time.");

/// An alias for `GuestMemoryAtomic<GuestMemoryMmap<B>>` to simplify code.
type GM<B> = GuestMemoryAtomic<GuestMemoryMmap<B>>;

#[derive(Debug)]
/// Errors related to vhost-user daemon.
pub enum Error {
    /// Failed to create a new vhost-user handler.
    NewVhostUserHandler(VhostUserHandlerError),
    /// Failed creating vhost-user backend listener.
    CreateBackendListener(VhostUserError),
    /// Failed creating vhost-user backend handler.
    CreateBackendReqHandler(VhostUserError),
    /// Failed creating listener socket
    CreateVhostUserListener(VhostUserError),
    /// Failed starting daemon thread.
    StartDaemon(std::io::Error),
    /// Failed waiting for daemon thread.
    WaitDaemon(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    /// Failed handling a vhost-user request.
    HandleRequest(VhostUserError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Error::NewVhostUserHandler(e) => write!(f, "cannot create vhost user handler: {e}"),
            Error::CreateBackendListener(e) => write!(f, "cannot create backend listener: {e}"),
            Error::CreateBackendReqHandler(e) => {
                write!(f, "cannot create backend req handler: {e}")
            }
            Error::CreateVhostUserListener(e) => {
                write!(f, "cannot create vhost-user listener: {e}")
            }
            Error::StartDaemon(e) => write!(f, "failed to start daemon: {e}"),
            Error::WaitDaemon(_e) => write!(f, "failed to wait for daemon exit"),
            Error::HandleRequest(e) => write!(f, "failed to handle request: {e}"),
        }
    }
}

/// Result of vhost-user daemon operations.
pub type Result<T> = std::result::Result<T, Error>;

struct ConnectionState {
    conn: UnixStream,
    shutdown_requested: AtomicBool,
}

/// Thread-safe handle to request shutdown of a running [`VhostUserDaemon`].
///
/// Safe to call multiple times or after the connection has already closed.
#[derive(Clone)]
pub struct ShutdownHandle {
    state: Arc<ConnectionState>,
}

impl ShutdownHandle {
    /// Request the daemon to shut down.
    pub fn shutdown(&self) {
        self.state.shutdown_requested.store(true, Ordering::Release);
        let _ = self.state.conn.shutdown(Shutdown::Both);
    }
}

/// Implement a simple framework to run a vhost-user service daemon.
///
/// This structure is the public API the backend is allowed to interact with in order to run
/// a fully functional vhost-user daemon.
///
/// `W` is the loop each vring worker thread runs. The default, [`VringEpollHandler`], is the
/// epoll loop that [`VhostUserDaemon::new`] builds for a [`VhostUserBackend`]; with the
/// `completion` feature, `new_completion` builds [`VringCompletionHandler`] loops for a
/// `VhostUserCompletionBackend`. See [`VringWorker`] and [`ProtocolBackend`].
pub struct VhostUserDaemon<T: ProtocolBackend<W>, W: VringWorker = VringEpollHandler<T>> {
    name: String,
    handler: Arc<Mutex<VhostUserHandler<T, W>>>,
    main_thread: Option<thread::JoinHandle<Result<()>>>,
    conn_state: Option<Arc<ConnectionState>>,
}

impl<T> VhostUserDaemon<T, VringEpollHandler<T>>
where
    T: VhostUserBackend + Clone + 'static,
    T::Bitmap: BitmapReplace + NewBitmap + Clone + Send + Sync,
    T::Vring: Clone + Send + Sync,
{
    /// Create the daemon instance, providing the backend implementation of `VhostUserBackend`.
    ///
    /// Under the hood, this will start a dedicated thread responsible for listening onto
    /// registered event. Those events can be vring events or custom events from the backend,
    /// but they get to be registered later during the sequence.
    pub fn new(
        name: String,
        backend: T,
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap<T::Bitmap>>,
    ) -> Result<Self> {
        let handler = Arc::new(Mutex::new(
            VhostUserHandler::new(backend, atomic_mem).map_err(Error::NewVhostUserHandler)?,
        ));

        Ok(VhostUserDaemon {
            name,
            handler,
            main_thread: None,
            conn_state: None,
        })
    }

    /// Retrieve the vring epoll handler.
    ///
    /// This is necessary to perform further actions like registering and unregistering some extra
    /// event file descriptors.
    pub fn get_epoll_handlers(&self) -> Vec<Arc<VringEpollHandler<T>>> {
        // Do not expect poisoned lock.
        self.handler.lock().unwrap().workers()
    }
}

#[cfg(all(windows, feature = "completion"))]
impl<T> VhostUserDaemon<T, VringCompletionHandler<T>>
where
    T: VhostUserCompletionBackend + Clone + 'static,
    T::Bitmap: BitmapReplace + NewBitmap + Clone + Send + Sync,
    T::Vring: Clone + Send + Sync,
{
    /// Create the daemon instance for a device that runs on the completion-port loop.
    ///
    /// One worker thread per entry of `queues_per_thread` starts here, each waiting on its own
    /// port. The device is given each port through `attach` before that thread starts, and
    /// [`get_ports`](Self::get_ports) returns the same ports afterwards.
    pub fn new_completion(
        name: String,
        backend: T,
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap<T::Bitmap>>,
    ) -> Result<Self> {
        let handler = Arc::new(Mutex::new(
            VhostUserHandler::new_completion(backend, atomic_mem)
                .map_err(Error::NewVhostUserHandler)?,
        ));

        Ok(VhostUserDaemon {
            name,
            handler,
            main_thread: None,
            conn_state: None,
        })
    }

    /// The port each worker thread waits on, in thread order: what `get_epoll_handlers` is to
    /// the epoll loop.
    pub fn get_ports(&self) -> Vec<Arc<Port>> {
        // Do not expect poisoned lock.
        self.handler
            .lock()
            .unwrap()
            .workers()
            .iter()
            .map(|worker| worker.port())
            .collect()
    }
}

impl<T, W> VhostUserDaemon<T, W>
where
    T: ProtocolBackend<W> + Clone + 'static,
    T::Bitmap: BitmapReplace + NewBitmap + Clone + Send + Sync,
    T::Vring: Clone + Send + Sync,
    W: VringWorker,
{
    fn reset_connection_state(&mut self) {
        self.conn_state = None;
    }

    /// Run a dedicated thread handling all requests coming through the socket.
    /// This runs in an infinite loop that should be terminating once the other
    /// end of the socket (the VMM) hangs up or [`request_shutdown`](Self::request_shutdown)
    /// is called.
    ///
    /// This function is the common code for starting a new daemon, no matter if
    /// it acts as a client or a server.
    fn start_daemon(
        &mut self,
        mut handler: BackendReqHandler<Mutex<VhostUserHandler<T, W>>>,
    ) -> Result<()> {
        let state = Arc::new(ConnectionState {
            conn: handler.try_clone_connection().map_err(Error::StartDaemon)?,
            shutdown_requested: AtomicBool::new(false),
        });

        let thread_state = state.clone();
        let handle = thread::Builder::new()
            .name(self.name.clone())
            .spawn(move || {
                let result = loop {
                    if let Err(e) = handler.handle_request().map_err(Error::HandleRequest) {
                        break Err(e);
                    }
                };
                let _ = thread_state.conn.shutdown(Shutdown::Both);
                result
            })
            .map_err(Error::StartDaemon)?;

        self.conn_state = Some(state);
        self.main_thread = Some(handle);

        Ok(())
    }

    /// Connect to the vhost-user socket and run a dedicated thread handling
    /// all requests coming through this socket. This runs in an infinite loop
    /// that should be terminating once the other end of the socket (the VMM)
    /// hangs up.
    pub fn start_client(&mut self, socket_path: &str) -> Result<()> {
        let backend_handler = BackendReqHandler::connect(socket_path, self.handler.clone())
            .map_err(Error::CreateBackendReqHandler)?;
        self.start_daemon(backend_handler)
    }

    /// Listen to the vhost-user socket and run a dedicated thread handling all requests coming
    /// through this socket.
    ///
    /// This runs in an infinite loop that should be terminating once the other end of the socket
    /// (the VMM) disconnects.
    ///
    /// *Note:* A convenience function [VhostUserDaemon::serve] exists that
    /// may be a better option than this for simple use-cases.
    pub fn start(&mut self, listener: &mut Listener) -> Result<()> {
        let mut backend_listener = BackendListener::new(listener, self.handler.clone())
            .map_err(Error::CreateBackendListener)?;
        let backend_handler = self.accept(&mut backend_listener)?;
        self.start_daemon(backend_handler)
    }

    fn accept(
        &self,
        backend_listener: &mut BackendListener<Mutex<VhostUserHandler<T, W>>>,
    ) -> Result<BackendReqHandler<Mutex<VhostUserHandler<T, W>>>> {
        loop {
            match backend_listener.accept() {
                Err(e) => return Err(Error::CreateBackendListener(e)),
                Ok(Some(v)) => return Ok(v),
                Ok(None) => continue,
            }
        }
    }

    /// Wait for the thread handling the vhost-user socket connection to terminate.
    ///
    /// *Note:* A convenience function [VhostUserDaemon::serve] exists that
    /// may be a better option than this for simple use-cases.
    pub fn wait(&mut self) -> Result<()> {
        let Some(handle) = self.main_thread.take() else {
            self.reset_connection_state();
            return Ok(());
        };

        let shutdown_requested = || {
            self.conn_state
                .as_ref()
                .is_some_and(|s| s.shutdown_requested.load(Ordering::Acquire))
        };

        let result = match handle.join().map_err(Error::WaitDaemon)? {
            Ok(()) => Ok(()),
            Err(Error::HandleRequest(VhostUserError::SocketBroken(_))) => Ok(()),
            Err(Error::HandleRequest(_)) if shutdown_requested() => Ok(()),
            Err(error) => Err(error),
        };

        self.reset_connection_state();

        result
    }

    /// Returns a handle to shut down the daemon, or `None` if not connected.
    pub fn shutdown_handle(&self) -> Option<ShutdownHandle> {
        self.conn_state
            .as_ref()
            .map(|s| ShutdownHandle { state: s.clone() })
    }

    /// Shut down the connection to unblock the daemon thread.
    pub fn request_shutdown(&self) {
        if let Some(handle) = self.shutdown_handle() {
            handle.shutdown();
        }
    }

    /// Bind to socket, handle a single connection and shutdown
    ///
    /// This is a convenience function that provides an easy way to handle the
    /// following actions without needing to call the low-level functions:
    /// - Create a listener
    /// - Start listening
    /// - Handle a single event
    /// - Send the exit event to all handler threads
    ///
    /// Internal `Err` results that indicate a device disconnect will be treated
    /// as success and `Ok(())` will be returned in those cases.
    ///
    /// *Note:* See [VhostUserDaemon::start] and [VhostUserDaemon::wait] if you
    /// need more flexibility.
    pub fn serve<P: AsRef<Path>>(&mut self, socket: P) -> Result<()> {
        let mut listener = Listener::new(socket, true).map_err(Error::CreateVhostUserListener)?;

        self.start(&mut listener)?;
        let result = self.wait();

        // Regardless of the result, we want to signal worker threads to exit
        self.handler.lock().unwrap().send_exit_event();

        // For this convenience function we are not treating certain "expected"
        // outcomes as error. Disconnects and partial messages can be usual
        // behaviour seen from quitting guests.
        match &result {
            Err(e) => match e {
                Error::HandleRequest(VhostUserError::Disconnected) => Ok(()),
                Error::HandleRequest(VhostUserError::PartialMessage) => Ok(()),
                _ => result,
            },
            _ => result,
        }
    }
}

impl<T: ProtocolBackend<W>, W: VringWorker> Drop for VhostUserDaemon<T, W> {
    fn drop(&mut self) {
        if let Some(state) = self.conn_state.take() {
            let _ = state.conn.shutdown(Shutdown::Both);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::backend::tests::MockVhostBackend;
    #[cfg(all(windows, feature = "completion"))]
    use super::completion_backend::tests::MockCompletionBackend;
    use super::*;
    #[cfg(unix)]
    use libc::EAGAIN;
    #[cfg(unix)]
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::Barrier;
    use std::time::Duration;
    #[cfg(windows)]
    use uds_windows::{UnixListener, UnixStream};
    use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    fn test_mem() -> GuestMemoryAtomic<GuestMemoryMmap<()>> {
        GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        )
    }

    // The connection tests below take any daemon, so that each loop runs the same test.

    /// Serve one connection that hangs up at once: `wait` reports the partial message, and a
    /// second `wait` has nothing to report.
    fn start_and_wait<T, W>(daemon: &mut VhostUserDaemon<T, W>)
    where
        T: ProtocolBackend<W> + Clone + 'static,
        T::Bitmap: BitmapReplace + NewBitmap + Clone + Send + Sync,
        T::Vring: Clone + Send + Sync,
        W: VringWorker,
    {
        let barrier = Arc::new(Barrier::new(2));
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("socket");

        thread::scope(|s| {
            s.spawn(|| {
                barrier.wait();
                let socket = UnixStream::connect(&path).unwrap();
                barrier.wait();
                drop(socket)
            });

            let mut listener = Listener::new(&path, false).unwrap();
            barrier.wait();
            daemon.start(&mut listener).unwrap();
            barrier.wait();
            // Above process generates a `HandleRequest(PartialMessage)` error.
            daemon.wait().unwrap_err();
            daemon.wait().unwrap();
        });
    }

    /// The same as `start_and_wait`, with the daemon connecting out as a client.
    fn start_client_and_wait<T, W>(daemon: &mut VhostUserDaemon<T, W>)
    where
        T: ProtocolBackend<W> + Clone + 'static,
        T::Bitmap: BitmapReplace + NewBitmap + Clone + Send + Sync,
        T::Vring: Clone + Send + Sync,
        W: VringWorker,
    {
        let barrier = Arc::new(Barrier::new(2));
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("socket");

        thread::scope(|s| {
            s.spawn(|| {
                let listener = UnixListener::bind(&path).unwrap();
                barrier.wait();
                let (stream, _) = listener.accept().unwrap();
                barrier.wait();
                drop(stream)
            });

            barrier.wait();
            daemon
                .start_client(path.as_path().to_str().unwrap())
                .unwrap();
            barrier.wait();
            // Above process generates a `HandleRequest(PartialMessage)` error.
            daemon.wait().unwrap_err();
            daemon.wait().unwrap();
        });
    }

    /// A shutdown requested while a client is connected makes `wait` return `Ok`, and the daemon
    /// can then serve another connection.
    fn shutdown_while_connected<T, W>(daemon: &mut VhostUserDaemon<T, W>)
    where
        T: ProtocolBackend<W> + Clone + 'static,
        T::Bitmap: BitmapReplace + NewBitmap + Clone + Send + Sync,
        T::Vring: Clone + Send + Sync,
        W: VringWorker,
    {
        let barrier = Arc::new(Barrier::new(2));
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("socket");

        thread::scope(|s| {
            let barrier_client = barrier.clone();
            let path_client = path.clone();
            let _client = s.spawn(move || {
                barrier_client.wait();
                let stream = UnixStream::connect(&path_client).unwrap();
                barrier_client.wait();
                drop(stream);
            });

            let mut listener = Listener::new(&path, false).unwrap();
            barrier.wait();
            daemon.start(&mut listener).unwrap();

            let handle = daemon.shutdown_handle().expect("daemon started");
            handle.shutdown();

            daemon.wait().unwrap();
            assert!(daemon.shutdown_handle().is_none());
            barrier.wait();

            let barrier = Arc::new(Barrier::new(2));
            let barrier_client = barrier.clone();
            let path_client = path.clone();
            let _client = s.spawn(move || {
                barrier_client.wait();
                let stream = UnixStream::connect(&path_client).unwrap();
                barrier_client.wait();
                drop(stream);
            });

            barrier.wait();
            daemon.start(&mut listener).unwrap();
            barrier.wait();
            daemon.wait().unwrap_err();
            assert!(daemon.shutdown_handle().is_none());
        });
    }

    /// Requesting shutdown twice is harmless.
    fn double_shutdown<T, W>(daemon: &mut VhostUserDaemon<T, W>)
    where
        T: ProtocolBackend<W> + Clone + 'static,
        T::Bitmap: BitmapReplace + NewBitmap + Clone + Send + Sync,
        T::Vring: Clone + Send + Sync,
        W: VringWorker,
    {
        let barrier = Arc::new(Barrier::new(2));
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("socket");

        thread::scope(|s| {
            let barrier_client = barrier.clone();
            let path_client = path.clone();
            let _client = s.spawn(move || {
                barrier_client.wait();
                let stream = UnixStream::connect(&path_client).unwrap();
                barrier_client.wait();
                drop(stream);
            });

            let mut listener = Listener::new(&path, false).unwrap();
            barrier.wait();
            daemon.start(&mut listener).unwrap();

            let handle = daemon.shutdown_handle().expect("daemon started");
            handle.shutdown();
            handle.shutdown();

            daemon.wait().unwrap();
            barrier.wait();
        });
    }

    #[test]
    fn test_new_daemon() {
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
        let mut daemon = VhostUserDaemon::new("test".to_owned(), backend, test_mem()).unwrap();

        let handlers = daemon.get_epoll_handlers();
        assert_eq!(handlers.len(), 2);

        start_and_wait(&mut daemon);
    }

    #[test]
    fn test_new_daemon_client() {
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
        let mut daemon = VhostUserDaemon::new("test".to_owned(), backend, test_mem()).unwrap();

        let handlers = daemon.get_epoll_handlers();
        assert_eq!(handlers.len(), 2);

        start_client_and_wait(&mut daemon);
    }

    #[test]
    fn test_daemon_serve() {
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
        let mut daemon =
            VhostUserDaemon::new("test".to_owned(), backend.clone(), test_mem()).unwrap();
        let tmpdir = tempfile::tempdir().unwrap();
        let socket_path = tmpdir.path().join("socket");

        thread::scope(|s| {
            s.spawn(|| {
                let _ = daemon.serve(&socket_path);
            });

            // We have no way to wait for when the server becomes available...
            // So we will have to spin!
            while !socket_path.exists() {
                thread::sleep(Duration::from_millis(10));
            }

            // Check that no exit events got triggered yet.
            //
            // Windows' `consume()` is intentionally lossy (see `vmm_sys_util::event`'s Windows
            // docs) — never blocks, always returns `Ok(())` — so there's no way to observe "not
            // yet signaled" there like a nonblocking read on an unsignaled Linux eventfd. Only the
            // positive check below has a Windows equivalent.
            #[cfg(unix)]
            for thread_id in 0..VhostUserBackend::queues_per_thread(&backend).len() {
                let fd = backend.exit_event(thread_id).unwrap();
                // Reading from exit fd should fail since nothing was written yet
                assert_eq!(
                    fd.0.consume().unwrap_err().raw_os_error().unwrap(),
                    EAGAIN,
                    "exit event should not have been raised yet!"
                );
            }

            let socket = UnixStream::connect(&socket_path).unwrap();
            // disconnect immediately again
            drop(socket);
        });

        // Check that exit events got triggered
        let backend = backend.lock().unwrap();
        for thread_id in 0..backend.queues_per_thread().len() {
            let fd = backend.exit_event(thread_id).unwrap();
            assert!(fd.0.consume().is_ok(), "No exit event was raised!");
        }
    }

    #[test]
    fn test_shutdown_while_connected() {
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
        let mut daemon = VhostUserDaemon::new("test".to_owned(), backend, test_mem()).unwrap();
        shutdown_while_connected(&mut daemon);
    }

    #[test]
    fn test_double_shutdown() {
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
        let mut daemon = VhostUserDaemon::new("test".to_owned(), backend, test_mem()).unwrap();
        double_shutdown(&mut daemon);
    }

    #[test]
    fn test_shutdown_handle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ShutdownHandle>();
    }

    #[cfg(all(windows, feature = "completion"))]
    mod completion {
        use super::*;
        use std::os::windows::io::AsRawHandle;

        type Backend = Arc<Mutex<MockCompletionBackend>>;

        fn new_daemon() -> (
            Backend,
            VhostUserDaemon<Backend, VringCompletionHandler<Backend>>,
        ) {
            let backend = Arc::new(Mutex::new(MockCompletionBackend::new()));
            let daemon =
                VhostUserDaemon::new_completion("test".to_owned(), backend.clone(), test_mem())
                    .unwrap();
            (backend, daemon)
        }

        #[test]
        fn test_new_daemon() {
            let (backend, mut daemon) = new_daemon();

            // One port per worker thread, and the device was attached to exactly those ports.
            let ports = daemon.get_ports();
            assert_eq!(ports.len(), 2);
            let attached = backend.lock().unwrap().ports().to_vec();
            assert_eq!(attached.len(), 2);
            for (port, attached) in ports.iter().zip(attached.iter()) {
                assert_eq!(port.as_raw_handle(), attached.as_raw_handle());
            }

            start_and_wait(&mut daemon);
        }

        #[test]
        fn test_new_daemon_client() {
            let (_backend, mut daemon) = new_daemon();
            assert_eq!(daemon.get_ports().len(), 2);
            start_client_and_wait(&mut daemon);
        }

        #[test]
        fn test_daemon_serve() {
            let (_backend, mut daemon) = new_daemon();
            let tmpdir = tempfile::tempdir().unwrap();
            let socket_path = tmpdir.path().join("socket");

            thread::scope(|s| {
                s.spawn(|| {
                    let _ = daemon.serve(&socket_path);
                });

                // We have no way to wait for when the server becomes available...
                // So we will have to spin!
                while !socket_path.exists() {
                    thread::sleep(Duration::from_millis(10));
                }

                let socket = UnixStream::connect(&socket_path).unwrap();
                // disconnect immediately again
                drop(socket);
            });

            // There is no exit event to read on this loop: `serve` posted the exit packet to
            // every worker's port, and dropping the daemon joins the worker threads, which
            // returns only if each loop saw its packet. A hang here is the failure.
            drop(daemon);
        }

        #[test]
        fn test_shutdown_while_connected() {
            let (_backend, mut daemon) = new_daemon();
            shutdown_while_connected(&mut daemon);
        }

        #[test]
        fn test_double_shutdown() {
            let (_backend, mut daemon) = new_daemon();
            double_shutdown(&mut daemon);
        }
    }
}
