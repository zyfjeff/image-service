// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use event_manager::{EventOps, EventSubscriber, Events};
use fuse_rs::api::Vfs;
use nydus_api::http_endpoint::{ApiError, ApiRequest, ApiResponsePayload, DaemonInfo, MountInfo};
use nydus_utils::{einval, enoent, eother, epipe, last_error};
use rafs::fs::{Rafs, RafsConfig};
use rafs::io_stats;
use std::fs::File;
use std::io::Result;
use std::ops::Deref;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use crate::SubscriberWrapper;

type RafsMounter = fn(MountInfo, &RafsConfig, &Arc<Vfs>) -> Result<()>;

pub struct ApiServer {
    id: String,
    version: String,
}

impl ApiServer {
    pub fn new(id: String, version: String) -> Result<Self> {
        Ok(ApiServer { id, version })
    }

    fn process_request(
        &self,
        api_receiver: &Receiver<ApiRequest>,
        mounter: RafsMounter,
        rafs_conf: &RafsConfig,
        vfs: &Arc<Vfs>,
    ) -> Result<()> {
        let api_request = api_receiver
            .recv()
            .map_err(|e| epipe!(format!("receive API channel failed {}", e)))?;

        match api_request {
            ApiRequest::DaemonInfo(sender) => {
                let response = DaemonInfo {
                    id: self.id.to_string(),
                    version: self.version.to_string(),
                    state: "Running".to_string(),
                };

                sender
                    .send(Ok(response).map(ApiResponsePayload::DaemonInfo))
                    .map_err(|e| epipe!(format!("send API response failed {}", e)))?;
            }
            ApiRequest::Mount(info, sender) => {
                let r = match mounter(info, rafs_conf, vfs) {
                    Ok(_) => Ok(ApiResponsePayload::Mount),
                    Err(e) => Err(ApiError::MountFailure(e)),
                };
                sender
                    .send(r)
                    .map_err(|e| epipe!(format!("send API response failed {}", e)))?;
            }
            ApiRequest::ConfigureDaemon(conf, sender) => {
                if let Ok(v) = conf.log_level.parse::<log::LevelFilter>() {
                    log::set_max_level(v);
                    sender.send(Ok(ApiResponsePayload::Empty)).unwrap();
                } else {
                    error!("Invalid log level passed, {}", conf.log_level);
                    sender.send(Err(ApiError::ResponsePayloadType)).unwrap();
                }
            }
            ApiRequest::ExportGlobalMetrics(sender, id) => {
                let resp;
                match io_stats::export_global_stats(&id) {
                    Ok(m) => resp = m,
                    Err(e) => resp = e,
                }
                // Even failed in sending, never leave this loop?
                if let Err(e) = sender.send(Ok(ApiResponsePayload::FsGlobalMetrics(resp))) {
                    error!("send API response failed {}", e);
                }
            }
            ApiRequest::ExportFilesMetrics(sender, id) => {
                // TODO: Use mount point name to refer to per rafs metrics.
                let resp;
                match io_stats::export_files_stats(&id) {
                    Ok(m) => resp = m,
                    Err(e) => resp = e,
                }
                if let Err(e) = sender.send(Ok(ApiResponsePayload::FsFilesMetrics(resp))) {
                    error!("send API response failed {}", e);
                }
            }
            ApiRequest::ExportAccessPatterns(sender, id) => {
                let resp;
                match io_stats::export_files_access_pattern(&id) {
                    Ok(m) => resp = m,
                    Err(e) => resp = e,
                }
                if let Err(e) = sender.send(Ok(ApiResponsePayload::FsFilesPatterns(resp))) {
                    error!("send API response failed {}", e);
                }
            }
        };

        Ok(())
    }
}

/// Mount Rafs per as to provided mount-info.
pub fn rafs_mount(info: MountInfo, default_rafs_conf: &RafsConfig, vfs: &Arc<Vfs>) -> Result<()> {
    match info.ops.as_str() {
        "mount" => {
            let mut rafs;

            if let Some(source) = info.source.as_ref() {
                let mut file = Box::new(File::open(source).map_err(|e| eother!(e))?)
                    as Box<dyn rafs::RafsIoRead>;

                rafs = match info.config.as_ref() {
                    Some(config) => {
                        let content = std::fs::read_to_string(config).map_err(|e| einval!(e))?;
                        let rafs_conf: RafsConfig =
                            serde_json::from_str(&content).map_err(|e| einval!(e))?;
                        Rafs::new(rafs_conf, &info.mountpoint, &mut file)?
                    }
                    None => Rafs::new(default_rafs_conf.clone(), &info.mountpoint, &mut file)?,
                };

                rafs.import(&mut file, None)?;

                match vfs.mount(Box::new(rafs), &info.mountpoint) {
                    Ok(()) => {
                        info!("rafs mounted");
                        Ok(())
                    }
                    Err(e) => Err(eother!(e)),
                }
            } else {
                Err(eother!("No source was provided!"))
            }
        }

        "umount" => match vfs.umount(&info.mountpoint) {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        },
        "update" => {
            info!("switch backend");
            let rafs_conf = match info.config.as_ref() {
                Some(config) => {
                    let content = std::fs::read_to_string(config).map_err(|e| einval!(e))?;
                    let rafs_conf: RafsConfig =
                        serde_json::from_str(&content).map_err(|e| einval!(e))?;
                    rafs_conf
                }
                None => {
                    return Err(enoent!("No rafs configuration was provided!"));
                }
            };

            let rootfs = vfs.get_rootfs(&info.mountpoint).map_err(|e| enoent!(e))?;
            let any_fs = rootfs.deref().as_any();
            if let Some(fs_swap) = any_fs.downcast_ref::<Rafs>() {
                if let Some(source) = info.source.as_ref() {
                    let mut file = Box::new(File::open(source).map_err(|e| last_error!(e))?)
                        as Box<dyn rafs::RafsIoRead>;

                    fs_swap
                        .update(&mut file, rafs_conf)
                        .map_err(|e| eother!(e))?;
                    Ok(())
                } else {
                    error!("no info.source is found, invalid mount info {:?}", info);
                    Err(enoent!("No source file was provided!"))
                }
            } else {
                Err(eother!("Can't swap fs"))
            }
        }
        _ => Err(einval!("Invalid op")),
    }
}

impl SubscriberWrapper for ApiSeverSubscriber {
    fn get_event_fd(&self) -> Result<EventFd> {
        self.event_fd.try_clone()
    }
}

pub struct ApiSeverSubscriber {
    event_fd: EventFd,
    server: ApiServer,
    api_receiver: Receiver<ApiRequest>,
    mounter: RafsMounter,
    rafs_conf: RafsConfig,
    vfs: Arc<Vfs>,
}

impl ApiSeverSubscriber {
    pub fn new(
        vfs: Arc<Vfs>,
        mounter: RafsMounter,
        server: ApiServer,
        api_receiver: Receiver<ApiRequest>,
    ) -> Result<Self> {
        match EventFd::new(0) {
            Ok(fd) => Ok(Self {
                event_fd: fd,
                rafs_conf: RafsConfig::new(),
                vfs,
                server,
                mounter,
                api_receiver,
            }),
            Err(e) => {
                error!("Creating event fd failed. {}", e);
                Err(e)
            }
        }
    }
}

impl EventSubscriber for ApiSeverSubscriber {
    fn process(&self, events: Events, event_ops: &mut EventOps) {
        self.event_fd
            .read()
            .map(|_| ())
            .map_err(|e| last_error!(e))
            .unwrap_or_else(|_| {});
        match events.event_set() {
            EventSet::IN => {
                self.server
                    .process_request(&self.api_receiver, self.mounter, &self.rafs_conf, &self.vfs)
                    .unwrap_or_else(|e| error!("API server process events failed, {}", e));
            }
            EventSet::ERROR => {
                error!("Got error on the monitored event.");
            }
            EventSet::HANG_UP => {
                event_ops
                    .remove(events)
                    .unwrap_or_else(|e| error!("Encountered error during cleanup, {}", e));
            }
            _ => {}
        }
    }

    fn init(&self, ops: &mut EventOps) {
        ops.add(Events::new(&self.event_fd, EventSet::IN))
            .expect("Cannot register event")
    }
}
