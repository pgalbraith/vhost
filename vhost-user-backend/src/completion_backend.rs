// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Traits for devices that run on the completion-port loop.
//!
//! [`VhostUserCompletionBackend`] and [`VhostUserCompletionBackendMut`] are
//! the completion-loop counterparts of `VhostUserBackend` and
//! `VhostUserBackendMut`: every protocol-facing method is the same, and only
//! the loop-facing ones differ. Where the epoll trait has `handle_event`,
//! `exit_event` and a registrar for extra descriptors, these have:
//!
//! - [`attach`](VhostUserCompletionBackend::attach), called once per worker
//!   thread before its loop starts, with the [`Port`] that thread waits on.
//!   A device that does its own I/O associates its handles with that port
//!   and submits operations on it; a device that only processes queues on a
//!   kick keeps the default, which does nothing.
//! - [`handle_kick`](VhostUserCompletionBackend::handle_kick), called when
//!   a vring's kick fires.
//! - [`handle_completion`](VhostUserCompletionBackend::handle_completion),
//!   called for everything else the port delivers: an operation the device
//!   submitted, a signal or timer it registered, or a packet posted under a
//!   key of its own.
//!
//! There is no exit event: the loop stops on a packet posted under a key it
//! reserves, so a device has nothing to create for that.
//!
//! KEYS - which are the loop's and which are the device's
//! ------------------------------------------------------
//!
//! Every packet the port delivers carries a key, and the loop sorts by it.
//! Keys `0` to `num_queues()` inclusive belong to the loop: a kick arrives
//! under the vring's index within its worker, and the exit packet under
//! `num_queues()`. A device registers its own signals and associates its
//! own handles under keys above `num_queues()`, and those come back through
//! `handle_completion` untouched. The same rule the epoll loop applies to
//! `register_listener`, without a call to enforce it, because the device
//! holds the port itself.
//!
//! As with the other pair, the only difference between the two traits is
//! mutability, and
//! ```ignore
//! impl<T: VhostUserCompletionBackendMut> VhostUserCompletionBackend for RwLock<T> { }
//! ```
//! is provided, along with the `Mutex` and `Arc` forms.

use std::fs::File;
use std::io::Result;
use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock};

use vhost::vhost_user::message::{
    VhostTransferStateDirection, VhostTransferStatePhase, VhostUserProtocolFeatures,
    VhostUserShMemConfig, VhostUserSharedMsg,
};
use vm_memory::bitmap::Bitmap;
use vmm_sys_util::completion::{Completion, Port};

use super::vring::VringT;
use super::GM;

/// Trait with interior mutability for devices on the completion-port loop.
///
/// To support multi-threading and asynchronous IO, we enforce `Send + Sync` bound.
pub trait VhostUserCompletionBackend: Send + Sync {
    type Bitmap: Bitmap + 'static;
    type Vring: VringT<GM<Self::Bitmap>>;

    /// Get number of queues supported.
    fn num_queues(&self) -> usize;

    /// Get maximum queue size supported.
    fn max_queue_size(&self) -> usize;

    /// Get available virtio features.
    fn features(&self) -> u64;

    /// Set acknowledged virtio features.
    fn acked_features(&self, _features: u64) {}

    /// Get available vhost protocol features.
    fn protocol_features(&self) -> VhostUserProtocolFeatures;

    /// Reset the emulated device state.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn reset_device(&self) {}

    /// Enable or disable the virtio EVENT_IDX feature
    fn set_event_idx(&self, enabled: bool);

    /// Get virtio device configuration.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        Vec::new()
    }

    /// Set virtio device configuration.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn set_config(&self, _offset: u32, _buf: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Update guest memory regions.
    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()>;

    /// This method retrieves a file descriptor for a shared object, identified by a unique UUID,
    /// which can be used by the front-end for DMA. If the shared object is found, it must return
    /// a File that the frontend can use. If the shared object does not exist the function returns
    /// `None` (indicating no file descriptor is available).
    ///
    /// This function returns a `Result`, returning an error if the backend does not implement this
    /// function.
    fn get_shared_object(&self, _uuid: VhostUserSharedMsg) -> Result<File> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support get shared object",
        ))
    }

    /// Get the map to map queue index to worker thread index.
    ///
    /// A return value of [2, 2, 4] means: the first two queues will be handled by worker thread 0,
    /// the following two queues will be handled by worker thread 1, and the last four queues will
    /// be handled by worker thread 2.
    fn queues_per_thread(&self) -> Vec<u64> {
        vec![0xffff_ffff]
    }

    /// Take the port worker thread `thread_index` waits on, before that thread's loop starts.
    ///
    /// Called once per worker thread, from the thread creating the daemon. A device that submits
    /// its own I/O keeps the `Arc` and associates its handles with the port under keys above
    /// `num_queues()` (see the module header). The default does nothing, which is right for a
    /// device that only processes its queues on a kick.
    fn attach(&self, _thread_index: usize, _port: Arc<Port>) -> Result<()> {
        Ok(())
    }

    /// A kick fired on `vrings[vring]`, which is enabled.
    ///
    /// `vrings` are the vrings of worker thread `thread_id`, and `vring` indexes them. The signal
    /// has already been consumed by the wait that noticed it, so there is nothing to read.
    fn handle_kick(&self, vring: u16, vrings: &[Self::Vring], thread_id: usize) -> Result<()>;

    /// The port delivered something other than a kick or the loop's exit packet: an operation
    /// this device submitted, a signal or timer it registered, or a packet posted under one of
    /// its own keys.
    ///
    /// An operation comes back inside the [`Completion`] with its buffer and whatever it held,
    /// which is the moment its memory may be reused.
    fn handle_completion(
        &self,
        completion: Completion,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> Result<()>;

    /// Initiate transfer of internal state for the purpose of migration to/from the back-end.
    ///
    /// Depending on `direction`, the state should either be saved (i.e. serialized and written to
    /// `file`) or loaded (i.e. read from `file` and deserialized). The back-end can choose to use
    /// a different channel than file. If so, it must return a File that the front-end can use.
    /// Note that this function must not block during transfer, i.e. I/O to/from `file` must be
    /// done outside of this function.
    fn set_device_state_fd(
        &self,
        _direction: VhostTransferStateDirection,
        _phase: VhostTransferStatePhase,
        _file: File,
    ) -> Result<Option<File>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support state transfer",
        ))
    }

    /// After transferring internal state, check for any resulting errors, including potential
    /// deserialization errors when loading state.
    ///
    /// Although this function return a `Result`, the front-end will not receive any details about
    /// this error.
    fn check_device_state(&self) -> Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support state transfer",
        ))
    }

    fn get_shmem_config(&self) -> Result<VhostUserShMemConfig> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support shared memory regions",
        ))
    }
}

/// Trait without interior mutability for devices on the completion-port loop.
pub trait VhostUserCompletionBackendMut: Send + Sync {
    type Bitmap: Bitmap + 'static;
    type Vring: VringT<GM<Self::Bitmap>>;

    /// Get number of queues supported.
    fn num_queues(&self) -> usize;

    /// Get maximum queue size supported.
    fn max_queue_size(&self) -> usize;

    /// Get available virtio features.
    fn features(&self) -> u64;

    /// Set acknowledged virtio features.
    fn acked_features(&mut self, _features: u64) {}

    /// Get available vhost protocol features.
    fn protocol_features(&self) -> VhostUserProtocolFeatures;

    /// Reset the emulated device state.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn reset_device(&mut self) {}

    /// Enable or disable the virtio EVENT_IDX feature
    fn set_event_idx(&mut self, enabled: bool);

    /// Get virtio device configuration.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        Vec::new()
    }

    /// Set virtio device configuration.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn set_config(&mut self, _offset: u32, _buf: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Update guest memory regions.
    fn update_memory(&mut self, mem: GM<Self::Bitmap>) -> Result<()>;

    /// This method retrieves a file descriptor for a shared object, identified by a unique UUID,
    /// which can be used by the front-end for DMA. If the shared object is found, it must return
    /// a File that the frontend can use. If the shared object does not exist the function returns
    /// `None` (indicating no file descriptor is available).
    ///
    /// This function returns a `Result`, returning an error if the backend does not implement this
    /// function.
    fn get_shared_object(&mut self, _uuid: VhostUserSharedMsg) -> Result<File> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support get shared object",
        ))
    }

    /// Get the map to map queue index to worker thread index.
    ///
    /// A return value of [2, 2, 4] means: the first two queues will be handled by worker thread 0,
    /// the following two queues will be handled by worker thread 1, and the last four queues will
    /// be handled by worker thread 2.
    fn queues_per_thread(&self) -> Vec<u64> {
        vec![0xffff_ffff]
    }

    /// Take the port worker thread `thread_index` waits on, before that thread's loop starts.
    ///
    /// See [`VhostUserCompletionBackend::attach`].
    fn attach(&mut self, _thread_index: usize, _port: Arc<Port>) -> Result<()> {
        Ok(())
    }

    /// A kick fired on `vrings[vring]`, which is enabled.
    ///
    /// See [`VhostUserCompletionBackend::handle_kick`].
    fn handle_kick(&mut self, vring: u16, vrings: &[Self::Vring], thread_id: usize) -> Result<()>;

    /// The port delivered something other than a kick or the loop's exit packet.
    ///
    /// See [`VhostUserCompletionBackend::handle_completion`].
    fn handle_completion(
        &mut self,
        completion: Completion,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> Result<()>;

    /// Initiate transfer of internal state for the purpose of migration to/from the back-end.
    ///
    /// Depending on `direction`, the state should either be saved (i.e. serialized and written to
    /// `file`) or loaded (i.e. read from `file` and deserialized).  Note that this function must
    /// not block during transfer, i.e. I/O to/from `file` must be done outside of this function.
    fn set_device_state_fd(
        &mut self,
        _direction: VhostTransferStateDirection,
        _phase: VhostTransferStatePhase,
        _file: File,
    ) -> Result<Option<File>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support state transfer",
        ))
    }

    /// After transferring internal state, check for any resulting errors, including potential
    /// deserialization errors when loading state.
    ///
    /// Although this function return a `Result`, the front-end will not receive any details about
    /// this error.
    fn check_device_state(&self) -> Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support state transfer",
        ))
    }

    fn get_shmem_config(&self) -> Result<VhostUserShMemConfig> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support shared memory regions",
        ))
    }
}

impl<T: VhostUserCompletionBackend> VhostUserCompletionBackend for Arc<T> {
    type Bitmap = T::Bitmap;
    type Vring = T::Vring;

    fn num_queues(&self) -> usize {
        self.deref().num_queues()
    }

    fn max_queue_size(&self) -> usize {
        self.deref().max_queue_size()
    }

    fn features(&self) -> u64 {
        self.deref().features()
    }

    fn acked_features(&self, features: u64) {
        self.deref().acked_features(features)
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        self.deref().protocol_features()
    }

    fn reset_device(&self) {
        self.deref().reset_device()
    }

    fn set_event_idx(&self, enabled: bool) {
        self.deref().set_event_idx(enabled)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        self.deref().get_config(offset, size)
    }

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<()> {
        self.deref().set_config(offset, buf)
    }

    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()> {
        self.deref().update_memory(mem)
    }

    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<File> {
        self.deref().get_shared_object(uuid)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.deref().queues_per_thread()
    }

    fn attach(&self, thread_index: usize, port: Arc<Port>) -> Result<()> {
        self.deref().attach(thread_index, port)
    }

    fn handle_kick(&self, vring: u16, vrings: &[Self::Vring], thread_id: usize) -> Result<()> {
        self.deref().handle_kick(vring, vrings, thread_id)
    }

    fn handle_completion(
        &self,
        completion: Completion,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> Result<()> {
        self.deref()
            .handle_completion(completion, vrings, thread_id)
    }

    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        file: File,
    ) -> Result<Option<File>> {
        self.deref().set_device_state_fd(direction, phase, file)
    }

    fn check_device_state(&self) -> Result<()> {
        self.deref().check_device_state()
    }

    fn get_shmem_config(&self) -> Result<VhostUserShMemConfig> {
        self.deref().get_shmem_config()
    }
}

impl<T: VhostUserCompletionBackendMut> VhostUserCompletionBackend for Mutex<T> {
    type Bitmap = T::Bitmap;
    type Vring = T::Vring;

    fn num_queues(&self) -> usize {
        self.lock().unwrap().num_queues()
    }

    fn max_queue_size(&self) -> usize {
        self.lock().unwrap().max_queue_size()
    }

    fn features(&self) -> u64 {
        self.lock().unwrap().features()
    }

    fn acked_features(&self, features: u64) {
        self.lock().unwrap().acked_features(features)
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        self.lock().unwrap().protocol_features()
    }

    fn reset_device(&self) {
        self.lock().unwrap().reset_device()
    }

    fn set_event_idx(&self, enabled: bool) {
        self.lock().unwrap().set_event_idx(enabled)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        self.lock().unwrap().get_config(offset, size)
    }

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<()> {
        self.lock().unwrap().set_config(offset, buf)
    }

    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()> {
        self.lock().unwrap().update_memory(mem)
    }

    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<File> {
        self.lock().unwrap().get_shared_object(uuid)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.lock().unwrap().queues_per_thread()
    }

    fn attach(&self, thread_index: usize, port: Arc<Port>) -> Result<()> {
        self.lock().unwrap().attach(thread_index, port)
    }

    fn handle_kick(&self, vring: u16, vrings: &[Self::Vring], thread_id: usize) -> Result<()> {
        self.lock().unwrap().handle_kick(vring, vrings, thread_id)
    }

    fn handle_completion(
        &self,
        completion: Completion,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> Result<()> {
        self.lock()
            .unwrap()
            .handle_completion(completion, vrings, thread_id)
    }

    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        file: File,
    ) -> Result<Option<File>> {
        self.lock()
            .unwrap()
            .set_device_state_fd(direction, phase, file)
    }

    fn check_device_state(&self) -> Result<()> {
        self.lock().unwrap().check_device_state()
    }

    fn get_shmem_config(&self) -> Result<VhostUserShMemConfig> {
        self.lock().unwrap().get_shmem_config()
    }
}

impl<T: VhostUserCompletionBackendMut> VhostUserCompletionBackend for RwLock<T> {
    type Bitmap = T::Bitmap;
    type Vring = T::Vring;

    fn num_queues(&self) -> usize {
        self.read().unwrap().num_queues()
    }

    fn max_queue_size(&self) -> usize {
        self.read().unwrap().max_queue_size()
    }

    fn features(&self) -> u64 {
        self.read().unwrap().features()
    }

    fn acked_features(&self, features: u64) {
        self.write().unwrap().acked_features(features)
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        self.read().unwrap().protocol_features()
    }

    fn reset_device(&self) {
        self.write().unwrap().reset_device()
    }

    fn set_event_idx(&self, enabled: bool) {
        self.write().unwrap().set_event_idx(enabled)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        self.read().unwrap().get_config(offset, size)
    }

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<()> {
        self.write().unwrap().set_config(offset, buf)
    }

    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()> {
        self.write().unwrap().update_memory(mem)
    }

    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<File> {
        self.write().unwrap().get_shared_object(uuid)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.read().unwrap().queues_per_thread()
    }

    fn attach(&self, thread_index: usize, port: Arc<Port>) -> Result<()> {
        self.write().unwrap().attach(thread_index, port)
    }

    fn handle_kick(&self, vring: u16, vrings: &[Self::Vring], thread_id: usize) -> Result<()> {
        self.write().unwrap().handle_kick(vring, vrings, thread_id)
    }

    fn handle_completion(
        &self,
        completion: Completion,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> Result<()> {
        self.write()
            .unwrap()
            .handle_completion(completion, vrings, thread_id)
    }

    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        file: File,
    ) -> Result<Option<File>> {
        self.write()
            .unwrap()
            .set_device_state_fd(direction, phase, file)
    }

    fn check_device_state(&self) -> Result<()> {
        self.read().unwrap().check_device_state()
    }

    fn get_shmem_config(&self) -> Result<VhostUserShMemConfig> {
        self.read().unwrap().get_shmem_config()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::VringRwLock;
    use uuid::Uuid;
    use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    /// The completion-loop twin of `backend::tests::MockVhostBackend`: the same protocol
    /// answers, kicks and completions counted, and the ports it was attached to kept.
    pub struct MockCompletionBackend {
        events: u64,
        completions: u64,
        event_idx: bool,
        acked_features: u64,
        ports: Vec<Arc<Port>>,
    }

    impl MockCompletionBackend {
        pub fn new() -> Self {
            MockCompletionBackend {
                events: 0,
                completions: 0,
                event_idx: false,
                acked_features: 0,
                ports: Vec::new(),
            }
        }

        /// Kicks handled so far.
        pub fn events(&self) -> u64 {
            self.events
        }

        /// Non-kick completions handled so far.
        pub fn completions(&self) -> u64 {
            self.completions
        }

        /// The ports `attach` was given, in thread order.
        pub fn ports(&self) -> &[Arc<Port>] {
            &self.ports
        }
    }

    impl VhostUserCompletionBackendMut for MockCompletionBackend {
        type Bitmap = ();
        type Vring = VringRwLock;

        fn num_queues(&self) -> usize {
            2
        }

        fn max_queue_size(&self) -> usize {
            256
        }

        fn features(&self) -> u64 {
            0xffff_ffff_ffff_ffff
        }

        fn acked_features(&mut self, features: u64) {
            self.acked_features = features;
        }

        fn protocol_features(&self) -> VhostUserProtocolFeatures {
            VhostUserProtocolFeatures::all()
        }

        fn reset_device(&mut self) {
            self.event_idx = false;
            self.events = 0;
            self.completions = 0;
            self.acked_features = 0;
        }

        fn set_event_idx(&mut self, enabled: bool) {
            self.event_idx = enabled;
        }

        fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
            assert_eq!(offset, 0x200);
            assert_eq!(size, 8);

            vec![0xa5u8; 8]
        }

        fn set_config(&mut self, offset: u32, buf: &[u8]) -> Result<()> {
            assert_eq!(offset, 0x200);
            assert_eq!(buf.len(), 8);
            assert_eq!(buf, &[0xa5u8; 8]);

            Ok(())
        }

        fn update_memory(&mut self, _atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>) -> Result<()> {
            Ok(())
        }

        fn get_shared_object(&mut self, _uuid: VhostUserSharedMsg) -> Result<File> {
            let file = tempfile::tempfile().unwrap();
            Ok(file)
        }

        fn queues_per_thread(&self) -> Vec<u64> {
            vec![1, 1]
        }

        fn attach(&mut self, _thread_index: usize, port: Arc<Port>) -> Result<()> {
            self.ports.push(port);
            Ok(())
        }

        fn handle_kick(
            &mut self,
            _vring: u16,
            _vrings: &[VringRwLock],
            _thread_id: usize,
        ) -> Result<()> {
            self.events += 1;

            Ok(())
        }

        fn handle_completion(
            &mut self,
            _completion: Completion,
            _vrings: &[VringRwLock],
            _thread_id: usize,
        ) -> Result<()> {
            self.completions += 1;

            Ok(())
        }
    }

    #[test]
    fn test_new_mock_backend_mutex() {
        let backend = Arc::new(Mutex::new(MockCompletionBackend::new()));

        assert_eq!(backend.num_queues(), 2);
        assert_eq!(backend.max_queue_size(), 256);
        assert_eq!(backend.features(), 0xffff_ffff_ffff_ffff);
        assert_eq!(
            backend.protocol_features(),
            VhostUserProtocolFeatures::all()
        );
        assert_eq!(backend.queues_per_thread(), [1, 1]);

        assert_eq!(backend.get_config(0x200, 8), vec![0xa5; 8]);
        backend.set_config(0x200, &[0xa5; 8]).unwrap();

        backend.acked_features(0xffff);
        assert_eq!(backend.lock().unwrap().acked_features, 0xffff);

        backend.set_event_idx(true);
        assert!(backend.lock().unwrap().event_idx);

        let port = Arc::new(Port::new().unwrap());
        backend.attach(0, port).unwrap();
        assert_eq!(backend.lock().unwrap().ports().len(), 1);

        let uuid = VhostUserSharedMsg {
            uuid: Uuid::new_v4(),
        };
        backend.get_shared_object(uuid).unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        backend.update_memory(mem).unwrap();

        backend.reset_device();
        assert!(backend.lock().unwrap().events == 0);
        assert!(!backend.lock().unwrap().event_idx);
        assert!(backend.lock().unwrap().acked_features == 0);
    }

    #[test]
    fn test_new_mock_backend_rwlock() {
        let backend = Arc::new(RwLock::new(MockCompletionBackend::new()));

        assert_eq!(backend.num_queues(), 2);
        assert_eq!(backend.max_queue_size(), 256);
        assert_eq!(backend.features(), 0xffff_ffff_ffff_ffff);
        assert_eq!(
            backend.protocol_features(),
            VhostUserProtocolFeatures::all()
        );
        assert_eq!(backend.queues_per_thread(), [1, 1]);

        assert_eq!(backend.get_config(0x200, 8), vec![0xa5; 8]);
        backend.set_config(0x200, &[0xa5; 8]).unwrap();

        backend.acked_features(0xffff);
        assert_eq!(backend.read().unwrap().acked_features, 0xffff);

        backend.set_event_idx(true);
        assert!(backend.read().unwrap().event_idx);

        let port = Arc::new(Port::new().unwrap());
        backend.attach(0, port).unwrap();
        assert_eq!(backend.read().unwrap().ports().len(), 1);

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        backend.update_memory(mem.clone()).unwrap();

        let uuid = VhostUserSharedMsg {
            uuid: Uuid::new_v4(),
        };
        backend.get_shared_object(uuid).unwrap();

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        backend
            .handle_kick(0x1, std::slice::from_ref(&vring), 0)
            .unwrap();
        backend
            .handle_completion(
                Completion::Posted {
                    key: 7,
                    bytes: 0,
                    pointer: 0,
                },
                &[vring],
                0,
            )
            .unwrap();
        assert_eq!(backend.read().unwrap().events(), 1);
        assert_eq!(backend.read().unwrap().completions(), 1);

        backend.reset_device();
        assert!(backend.read().unwrap().events == 0);
        assert!(!backend.read().unwrap().event_idx);
        assert!(backend.read().unwrap().acked_features == 0);
    }
}
