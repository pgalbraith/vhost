// Copyright 2026 rust-vmm Authors or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! The half of a device the control channel talks to, whichever loop the
//! device runs on.

use std::fs::File;
use std::io::Result;

use vhost::vhost_user::message::{
    VhostTransferStateDirection, VhostTransferStatePhase, VhostUserProtocolFeatures,
    VhostUserShMemConfig, VhostUserSharedMsg,
};
#[cfg(unix)]
use vhost::vhost_user::{Backend, GpuBackend};
use vm_memory::bitmap::Bitmap;

use super::backend::VhostUserBackend;
#[cfg(all(windows, feature = "completion"))]
use super::completion_backend::VhostUserCompletionBackend;
#[cfg(all(windows, feature = "completion"))]
use super::completion_loop::VringCompletionHandler;
use super::event_loop::VringEpollHandler;
use super::vring::VringT;
use super::GM;

/// The methods every device has whichever loop it runs on: features,
/// configuration, memory, state transfer. `VhostUserHandler` bounds on this
/// and never sees the loop-facing methods.
///
/// Nothing implements this by hand. Every [`VhostUserBackend`] is a
/// `ProtocolBackend<VringEpollHandler<Self>>`, and with the `completion`
/// feature every `VhostUserCompletionBackend` is a
/// `ProtocolBackend<VringCompletionHandler<Self>>`. The loop type parameter
/// is what lets those two blanket implementations coexist: without it they
/// would overlap, since Rust cannot know that no type implements both device
/// traits.
pub trait ProtocolBackend<W>: Send + Sync {
    type Bitmap: Bitmap + 'static;
    type Vring: VringT<GM<Self::Bitmap>>;

    fn num_queues(&self) -> usize;
    fn max_queue_size(&self) -> usize;
    fn features(&self) -> u64;
    fn acked_features(&self, features: u64);
    fn protocol_features(&self) -> VhostUserProtocolFeatures;
    fn reset_device(&self);
    fn set_event_idx(&self, enabled: bool);
    fn get_config(&self, offset: u32, size: u32) -> Vec<u8>;
    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<()>;
    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()>;
    #[cfg(unix)]
    fn set_backend_req_fd(&self, backend: Backend);
    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<File>;
    #[cfg(unix)]
    fn set_gpu_socket(&self, gpu_backend: GpuBackend) -> Result<()>;
    fn queues_per_thread(&self) -> Vec<u64>;
    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        file: File,
    ) -> Result<Option<File>>;
    fn check_device_state(&self) -> Result<()>;
    fn get_shmem_config(&self) -> Result<VhostUserShMemConfig>;
}

impl<T: VhostUserBackend> ProtocolBackend<VringEpollHandler<T>> for T {
    type Bitmap = T::Bitmap;
    type Vring = T::Vring;

    fn num_queues(&self) -> usize {
        VhostUserBackend::num_queues(self)
    }

    fn max_queue_size(&self) -> usize {
        VhostUserBackend::max_queue_size(self)
    }

    fn features(&self) -> u64 {
        VhostUserBackend::features(self)
    }

    fn acked_features(&self, features: u64) {
        VhostUserBackend::acked_features(self, features)
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserBackend::protocol_features(self)
    }

    fn reset_device(&self) {
        VhostUserBackend::reset_device(self)
    }

    fn set_event_idx(&self, enabled: bool) {
        VhostUserBackend::set_event_idx(self, enabled)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        VhostUserBackend::get_config(self, offset, size)
    }

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<()> {
        VhostUserBackend::set_config(self, offset, buf)
    }

    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()> {
        VhostUserBackend::update_memory(self, mem)
    }

    #[cfg(unix)]
    fn set_backend_req_fd(&self, backend: Backend) {
        VhostUserBackend::set_backend_req_fd(self, backend)
    }

    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<File> {
        VhostUserBackend::get_shared_object(self, uuid)
    }

    #[cfg(unix)]
    fn set_gpu_socket(&self, gpu_backend: GpuBackend) -> Result<()> {
        VhostUserBackend::set_gpu_socket(self, gpu_backend)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        VhostUserBackend::queues_per_thread(self)
    }

    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        file: File,
    ) -> Result<Option<File>> {
        VhostUserBackend::set_device_state_fd(self, direction, phase, file)
    }

    fn check_device_state(&self) -> Result<()> {
        VhostUserBackend::check_device_state(self)
    }

    fn get_shmem_config(&self) -> Result<VhostUserShMemConfig> {
        VhostUserBackend::get_shmem_config(self)
    }
}

#[cfg(all(windows, feature = "completion"))]
impl<T: VhostUserCompletionBackend> ProtocolBackend<VringCompletionHandler<T>> for T {
    type Bitmap = T::Bitmap;
    type Vring = T::Vring;

    fn num_queues(&self) -> usize {
        VhostUserCompletionBackend::num_queues(self)
    }

    fn max_queue_size(&self) -> usize {
        VhostUserCompletionBackend::max_queue_size(self)
    }

    fn features(&self) -> u64 {
        VhostUserCompletionBackend::features(self)
    }

    fn acked_features(&self, features: u64) {
        VhostUserCompletionBackend::acked_features(self, features)
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserCompletionBackend::protocol_features(self)
    }

    fn reset_device(&self) {
        VhostUserCompletionBackend::reset_device(self)
    }

    fn set_event_idx(&self, enabled: bool) {
        VhostUserCompletionBackend::set_event_idx(self, enabled)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        VhostUserCompletionBackend::get_config(self, offset, size)
    }

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<()> {
        VhostUserCompletionBackend::set_config(self, offset, buf)
    }

    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()> {
        VhostUserCompletionBackend::update_memory(self, mem)
    }

    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<File> {
        VhostUserCompletionBackend::get_shared_object(self, uuid)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        VhostUserCompletionBackend::queues_per_thread(self)
    }

    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        file: File,
    ) -> Result<Option<File>> {
        VhostUserCompletionBackend::set_device_state_fd(self, direction, phase, file)
    }

    fn check_device_state(&self) -> Result<()> {
        VhostUserCompletionBackend::check_device_state(self)
    }

    fn get_shmem_config(&self) -> Result<VhostUserShMemConfig> {
        VhostUserCompletionBackend::get_shmem_config(self)
    }
}
