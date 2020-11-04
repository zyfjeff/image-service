// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::convert::From;
use std::fs::File;
use std::ops::Deref;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use event_manager::{EventOps, EventSubscriber, Events};
use fuse_rs::api::Vfs;
use nix::sys::signal::{kill, SIGTERM};
use nix::unistd::Pid;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use nydus_api::http_endpoint::{
    ApiError, ApiRequest, ApiResponse, ApiResponsePayload, ApiResult, DaemonConf, DaemonErrorKind,
    DaemonInfo, MountInfo,
};
use nydus_utils::{einval, enoent, eother, epipe, last_error};
use rafs::fs::{Rafs, RafsConfig};
use rafs::io_stats;

use crate::daemon::{DaemonError, NydusDaemon};
#[cfg(fusedev)]
use crate::fusedev::FusedevDaemon;
use crate::SubscriberWrapper;

pub struct ApiServer {
    version: String,
    to_http: Sender<ApiResponse>,
    daemon: Arc<dyn NydusDaemon>,
}

type Result<T> = ApiResult<T>;

impl From<DaemonError> for DaemonErrorKind {
    fn from(e: DaemonError) -> Self {
        use DaemonError::*;
        match e {
            NoResource => DaemonErrorKind::NoResource,
            NotReady => DaemonErrorKind::NotReady,
            SendFd => DaemonErrorKind::SendFd,
            RecvFd => DaemonErrorKind::RecvFd,
            _ => DaemonErrorKind::Other,
        }
    }
}

impl ApiServer {
    pub fn new(
        version: String,
        to_http: Sender<ApiResponse>,
        daemon: Arc<dyn NydusDaemon>,
    ) -> std::io::Result<Self> {
        Ok(ApiServer {
            version,
            to_http,
            daemon,
        })
    }

    fn process_request(
        &self,
        from_http: &Receiver<ApiRequest>,
        rafs_conf: &RafsConfig,
        vfs: &Vfs,
    ) -> std::io::Result<()> {
        let request = from_http
            .recv()
            .map_err(|e| epipe!(format!("receive API channel failed {}", e)))?;

        let resp = match request {
            ApiRequest::DaemonInfo => self.daemon_info(),
            ApiRequest::Mount(info) => Self::do_mount(info, rafs_conf, vfs),
            ApiRequest::ConfigureDaemon(conf) => self.configure_daemon(conf),
            ApiRequest::ExportGlobalMetrics(id) => Self::export_global_metrics(id),
            ApiRequest::ExportFilesMetrics(id) => Self::export_files_metrics(id),
            ApiRequest::ExportAccessPatterns(id) => Self::export_access_patterns(id),
            ApiRequest::SendFuseFd => self.send_fuse_fd(),
            ApiRequest::Takeover => self.do_takeover(),
            ApiRequest::Exit => self.do_exit(),
        };

        self.respond(resp);

        Ok(())
    }

    fn respond(&self, resp: Result<ApiResponsePayload>) {
        if let Err(e) = self.to_http.send(resp) {
            error!("send API response failed {}", e);
        }
    }

    fn daemon_info(&self) -> ApiResponse {
        let d = self.daemon.as_ref();

        let response = DaemonInfo {
            version: self.version.to_string(),
            id: d.id(),
            supervisor: d.supervisor(),
            state: d.get_state().to_string(),
        };

        Ok(ApiResponsePayload::DaemonInfo(response))
    }

    fn do_mount(info: MountInfo, rafs_conf: &RafsConfig, vfs: &Vfs) -> ApiResponse {
        rafs_mount(info, &rafs_conf, vfs)
            .map(|_| ApiResponsePayload::Empty)
            .map_err(ApiError::MountFailure)
    }

    fn configure_daemon(&self, conf: DaemonConf) -> ApiResponse {
        conf.log_level
            .parse::<log::LevelFilter>()
            .map_err(|e| {
                error!("Invalid log level passed, {}", e);
                ApiError::ResponsePayloadType
            })
            .map(|v| {
                log::set_max_level(v);
                ApiResponsePayload::Empty
            })
    }

    fn export_global_metrics(id: Option<String>) -> ApiResponse {
        io_stats::export_global_stats(&id)
            .map(ApiResponsePayload::FsGlobalMetrics)
            .map_err(|e| ApiError::Metrics(format!("{:?}", e)))
    }

    fn export_files_metrics(id: Option<String>) -> ApiResponse {
        // TODO: Use mount point name to refer to per rafs metrics.
        io_stats::export_files_stats(&id)
            .map(ApiResponsePayload::FsFilesMetrics)
            .map_err(|e| ApiError::Metrics(format!("{:?}", e)))
    }

    fn export_access_patterns(id: Option<String>) -> ApiResponse {
        io_stats::export_files_access_pattern(&id)
            .map(ApiResponsePayload::FsFilesPatterns)
            .map_err(|e| ApiError::Metrics(format!("{:?}", e)))
    }

    fn send_fuse_fd(&self) -> ApiResponse {
        let d = self.daemon.as_ref();

        d.save()
            .map(|_| {
                info!("save fuse fd to uds server");
                ApiResponsePayload::Empty
            })
            .map_err(|e| ApiError::DaemonAbnormal(e.into()))
    }

    /// External supervisor wants this instance to fetch `/dev/fuse` fd. Before
    /// invoking this method, supervisor should already listens on a Unix socket and
    /// waits for connection from this instance. Then supervisor should send the *fd*
    /// back. Note, the http response does not mean this process already finish Takeover
    /// procedure. Supervisor has to continuously query the state of Nydusd until it gets
    /// to *RUNNING*, which means new Nydusd has successfully serve as a fuse server.
    fn do_takeover(&self) -> ApiResponse {
        let d = self.daemon.as_ref();
        d.trigger_takeover()
            .map(|_| {
                info!("restore fuse fd from uds server");
                ApiResponsePayload::Empty
            })
            .map_err(|e| ApiError::DaemonAbnormal(e.into()))
    }

    /// External supervisor wants this instance to exit. But it can't just die leave
    /// some pending or in-flight fuse messages un-handled. So this method guarantees
    /// all fuse messages read from kernel are handled and replies are sent back.
    /// Before http response are sent back, this must can ensure that current process
    /// has absolutely stopped. Otherwise, multiple processes might read from single
    /// fuse session simultaneously.
    fn do_exit(&self) -> ApiResponse {
        let d = self.daemon.as_ref();
        d.trigger_exit()
            .map(|_| {
                info!("exit daemon by http request");
                ApiResponsePayload::Empty
            })
            .map_err(|e| ApiError::DaemonAbnormal(e.into()))?;

        // Should be reliable since this Api server works under event manager.
        kill(Pid::this(), SIGTERM).unwrap_or_else(|e| error!("Send signal error. {}", e));

        Ok(ApiResponsePayload::Empty)
    }
}

fn parse_rafs_config(p: impl AsRef<Path>) -> Option<RafsConfig> {
    if let Ok(content) = std::fs::read_to_string(p) {
        if let Ok(rafs_conf) = serde_json::from_str::<RafsConfig>(&content) {
            return Some(rafs_conf);
        }
    }
    None
}

/// Mount Rafs per as to provided mount-info.
pub fn rafs_mount(
    info: MountInfo,
    default_rafs_conf: &RafsConfig,
    vfs: &Vfs,
) -> std::io::Result<()> {
    match info.ops.as_str() {
        "mount" => {
            // As `umount` op has nothing to do with `source`, the body can have no `source`.
            let source = info
                .source
                .ok_or_else(|| enoent!("No source file is provided!"))?;

            let rafs_config = match info.config.as_ref() {
                Some(config) => {
                    parse_rafs_config(config).ok_or_else(|| einval!("Fail in parsing config"))?
                }
                None => default_rafs_conf.clone(),
            };

            let mut file =
                Box::new(File::open(source).map_err(|e| eother!(e))?) as Box<dyn rafs::RafsIoRead>;
            let mut rafs = Rafs::new(rafs_config, &info.mountpoint, &mut file)?;
            rafs.import(&mut file, None)?;

            vfs.mount(Box::new(rafs), &info.mountpoint).map_err(|e| {
                eother!(e);
                e
            })?;

            info!("rafs mounted");
            Ok(())
        }
        "update" => {
            info!("switch backend");

            // As `umount` op has nothing to do with `source`, the body can have no `source`.
            let source = info
                .source
                .ok_or_else(|| enoent!("No source file is provided!"))?;

            let config = info
                .config
                .as_ref()
                .ok_or_else(|| enoent!("No rafs configuration was provided!"))?;

            // Safe to unwrap since we already checked if `config` is None or not above.
            let rafs_conf =
                parse_rafs_config(config).ok_or_else(|| einval!("Fail in parsing config"))?;

            let rootfs = vfs.get_rootfs(&info.mountpoint).map_err(|e| enoent!(e))?;
            let any_fs = rootfs.deref().as_any();
            let fs_swap = any_fs.downcast_ref::<Rafs>().ok_or_else(|| {
                error!("Can't downcast!");
                einval!()
            })?;
            let mut file = Box::new(File::open(source).map_err(|e| last_error!(e))?)
                as Box<dyn rafs::RafsIoRead>;

            fs_swap
                .update(&mut file, rafs_conf)
                .map_err(|e| eother!(e))?;
            Ok(())
        }
        "umount" => vfs.umount(&info.mountpoint),
        _ => Err(einval!("Invalid op")),
    }
}

impl SubscriberWrapper for ApiSeverSubscriber {
    fn get_event_fd(&self) -> std::io::Result<EventFd> {
        self.event_fd.try_clone()
    }
}

pub struct ApiSeverSubscriber {
    event_fd: EventFd,
    server: ApiServer,
    api_receiver: Receiver<ApiRequest>,
    rafs_conf: RafsConfig,
    vfs: Arc<Vfs>,
}

impl ApiSeverSubscriber {
    pub fn new(
        vfs: Arc<Vfs>,
        server: ApiServer,
        api_receiver: Receiver<ApiRequest>,
    ) -> std::io::Result<Self> {
        match EventFd::new(0) {
            Ok(fd) => Ok(Self {
                event_fd: fd,
                rafs_conf: RafsConfig::new(),
                vfs,
                server,
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
                    .process_request(&self.api_receiver, &self.rafs_conf, &self.vfs)
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
