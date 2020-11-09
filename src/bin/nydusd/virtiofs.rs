// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::io::Result;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::thread;

use libc::EFD_NONBLOCK;

use fuse_rs::api::{server::Server, Vfs};
use fuse_rs::transport::{FsCacheReqHandler, Reader, Writer};

use vhost_rs::vhost_user::{message::*, Listener, SlaveFsCacheReq};
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring};
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

use nydus_utils::eother;
use upgrade_manager::UpgradeManager;

use crate::daemon;
use daemon::{DaemonError, DaemonResult, DaemonState, NydusDaemon};

const VIRTIO_F_VERSION_1: u32 = 32;
const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;

// The guest queued an available buffer for the high priority queue.
const HIPRIO_QUEUE_EVENT: u16 = 0;
// The guest queued an available buffer for the request queue.
const REQ_QUEUE_EVENT: u16 = 1;
// The device has been dropped.
const KILL_EVENT: u16 = 2;

/// TODO: group virtiofs code into a different file
type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[allow(dead_code)]
struct VhostUserFsBackendHandler {
    backend: Mutex<VhostUserFsBackend>,
}

struct VhostUserFsBackend {
    mem: Option<GuestMemoryMmap>,
    kill_evt: EventFd,
    server: Arc<Server<Arc<Vfs>>>,
    // handle request from slave to master
    vu_req: Option<SlaveFsCacheReq>,
    used_descs: Vec<(u16, u32)>,
}

impl VhostUserFsBackendHandler {
    fn new(vfs: Arc<Vfs>) -> Result<Self> {
        let backend = VhostUserFsBackend {
            mem: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(DaemonError::Epoll)?,
            server: Arc::new(Server::new(vfs)),
            vu_req: None,
            used_descs: Vec::with_capacity(QUEUE_SIZE),
        };
        Ok(VhostUserFsBackendHandler {
            backend: Mutex::new(backend),
        })
    }
}

impl VhostUserFsBackend {
    // There's no way to recover if error happens during processing a virtq, let the caller
    // to handle it.
    fn process_queue(&mut self, vring: &mut Vring) -> Result<()> {
        let mem = self.mem.as_ref().ok_or(DaemonError::NoMemoryConfigured)?;

        while let Some(avail_desc) = vring.mut_queue().iter(mem).next() {
            let head_index = avail_desc.index();
            let reader = Reader::new(mem, avail_desc.clone())
                .map_err(DaemonError::InvalidDescriptorChain)?;
            let writer =
                Writer::new(mem, avail_desc).map_err(DaemonError::InvalidDescriptorChain)?;

            let total = self
                .server
                .handle_message(
                    reader,
                    writer,
                    self.vu_req
                        .as_mut()
                        .map(|x| x as &mut dyn FsCacheReqHandler),
                )
                .map_err(DaemonError::ProcessQueue)?;

            self.used_descs.push((head_index, total as u32));
        }

        if !self.used_descs.is_empty() {
            for (desc_index, data_sz) in &self.used_descs {
                trace!(
                    "used desc index {} bytes {} total_used {}",
                    desc_index,
                    data_sz,
                    self.used_descs.len()
                );
                vring.mut_queue().add_used(mem, *desc_index, *data_sz);
            }
            self.used_descs.clear();
            vring.signal_used_queue().unwrap();
        }

        Ok(())
    }
}

impl VhostUserBackend for VhostUserFsBackendHandler {
    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1 | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::SLAVE_REQ
    }

    fn set_event_idx(&mut self, _enabled: bool) {}

    fn update_memory(&mut self, mem: GuestMemoryMmap) -> VhostUserBackendResult<()> {
        self.backend.lock().unwrap().mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &self,
        index: u16,
        evset: epoll::Events,
        vrings: &[Arc<RwLock<Vring>>],
        _thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != epoll::Events::EPOLLIN {
            return Err(DaemonError::HandleEventNotEpollIn.into());
        }

        match index {
            HIPRIO_QUEUE_EVENT => {
                let mut vring = vrings[HIPRIO_QUEUE_EVENT as usize].write().unwrap();
                // high priority requests are also just plain fuse requests, just in a
                // different queue
                self.backend.lock().unwrap().process_queue(&mut vring)?;
            }
            x if x >= REQ_QUEUE_EVENT && x < vrings.len() as u16 => {
                let mut vring = vrings[x as usize].write().unwrap();
                self.backend.lock().unwrap().process_queue(&mut vring)?;
            }
            _ => return Err(DaemonError::HandleEventUnknownEvent.into()),
        }

        Ok(false)
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventFd, Option<u16>)> {
        Some((
            self.backend.lock().unwrap().kill_evt.try_clone().unwrap(),
            Some(KILL_EVENT),
        ))
    }

    fn set_slave_req_fd(&mut self, vu_req: SlaveFsCacheReq) {
        self.backend.lock().unwrap().vu_req = Some(vu_req);
    }
}

struct VirtiofsDaemon<S: VhostUserBackend> {
    vfs: Arc<Vfs>,
    daemon: Mutex<VhostUserDaemon<S>>,
    sock: String,
    id: Option<String>,
    supervisor: Option<String>,
    upgrade_mgr: Option<Mutex<UpgradeManager>>,
}

impl<S: VhostUserBackend> NydusDaemon for VirtiofsDaemon<S> {
    fn start(&self) -> DaemonResult<()> {
        let listener = Listener::new(&self.sock, true)
            .map_err(|e| DaemonError::StartService(format!("{:?}", e)))?;

        self.daemon
            .lock()
            .unwrap()
            .start(listener)
            .map_err(|e| DaemonError::StartService(format!("{:?}", e)))
    }

    fn wait(&self) -> DaemonResult<()> {
        self.daemon
            .lock()
            .unwrap()
            .wait()
            .map_err(|e| DaemonError::WaitDaemon(eother!(e)))
    }

    fn stop(&self) -> DaemonResult<()> {
        /* TODO: find a way to kill backend
        let kill_evt = &backend.read().unwrap().kill_evt;
        if let Err(e) = kill_evt.write(1) {}
        */
        Ok(())
    }

    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_state(&self) -> DaemonState {
        unimplemented!();
    }

    fn set_state(&self, _state: DaemonState) {
        unimplemented!();
    }

    fn save(&self) -> DaemonResult<()> {
        unimplemented!();
    }

    fn restore(&self) -> DaemonResult<()> {
        unimplemented!();
    }

    fn get_vfs(&self) -> &Vfs {
        &self.vfs
    }

    fn get_upgrade_mgr(&self) -> Option<MutexGuard<UpgradeManager>> {
        self.upgrade_mgr.as_ref().map(|mgr| mgr.lock().unwrap())
    }
}

pub fn create_nydus_daemon(
    id: Option<String>,
    sock: &str,
    vfs: Arc<Vfs>,
) -> Result<Arc<dyn NydusDaemon + Send>> {
    let vu_daemon = VhostUserDaemon::new(
        String::from("vhost-user-fs-backend"),
        Arc::new(RwLock::new(VhostUserFsBackendHandler::new(vfs.clone())?)),
    )
    .map_err(|e| DaemonError::DaemonFailure(format!("{:?}", e)))?;

    let daemon = Arc::new(VirtiofsDaemon {
        vfs,
        daemon: Mutex::new(vu_daemon),
        sock: sock.to_string(),
        id,
        supervisor: None,
        upgrade_mgr: None,
    });

    let d = daemon.clone();
    thread::Builder::new()
        .name("virtiofs_listener".to_string())
        .spawn(move || {
            d.start().expect("Failed to start virtiofs daemon");
        })
        .map_err(DaemonError::ThreadSpawn)?;

    Ok(daemon)
}
