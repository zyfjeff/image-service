// Copyright 2020 Ant Financial. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use(crate_version, crate_authors)]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate rafs;
extern crate serde_json;
extern crate stderrlog;

use event_manager::{EventManager, EventOps, EventSubscriber, Events, SubscriberOps};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use std::fs::File;
use std::io::{Read, Result};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};

use std::sync::{Arc, Mutex};
use std::{io, process};

use nix::sys::signal;
use rlimit::{rlim, Resource};

use clap::{App, Arg};
use fuse_rs::api::{Vfs, VfsOptions};
use fuse_rs::passthrough::{Config, PassthroughFs};

use nydus_api::http::start_http_thread;
use nydus_api::http_endpoint::{ApiError, ApiRequest, ApiResponsePayload, DaemonInfo, MountInfo};
use nydus_utils::{einval, enoent, eother, epipe, last_error, log_level_to_verbosity};
use rafs::fs::{Rafs, RafsConfig};
use rafs::io_stats;

mod daemon;
use daemon::Error;

#[cfg(feature = "virtiofsd")]
mod virtiofs;
#[cfg(feature = "virtiofsd")]
use virtiofs::create_nydus_daemon;
#[cfg(feature = "fusedev")]
mod fusedev;
#[cfg(feature = "fusedev")]
use fusedev::create_nydus_daemon;

lazy_static! {
    static ref EVENT_MANAGER_RUN: AtomicBool = AtomicBool::new(true);
    static ref EXIT_EVTFD: Mutex::<Option<EventFd>> = Mutex::<Option<EventFd>>::default();
}

type RafsMounter = fn(MountInfo, &RafsConfig, &Arc<Vfs>) -> Result<()>;
struct ApiSeverSubscriber {
    event_fd: EventFd,
    server: ApiServer,
    api_receiver: Receiver<ApiRequest>,
    mounter: RafsMounter,
    rafs_conf: RafsConfig,
    vfs: Arc<Vfs>,
}

struct NydusDaemonSubscriber {
    event_fd: EventFd,
}

impl NydusDaemonSubscriber {
    fn new() -> Result<Self> {
        match EventFd::new(0) {
            Ok(fd) => Ok(Self { event_fd: fd }),
            Err(e) => {
                error!("Creating event fd failed. {}", e);
                Err(e)
            }
        }
    }
}

impl SubscriberWrapper for NydusDaemonSubscriber {
    fn get_event_fd(&self) -> Result<EventFd> {
        self.event_fd.try_clone()
    }
}

impl EventSubscriber for NydusDaemonSubscriber {
    fn process(&self, events: Events, event_ops: &mut EventOps) {
        self.event_fd
            .read()
            .map(|_| ())
            .map_err(|e| last_error!(e))
            .unwrap_or_else(|_| {});

        match events.event_set() {
            EventSet::IN => {
                EVENT_MANAGER_RUN.store(false, Ordering::Relaxed);
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

impl ApiSeverSubscriber {
    fn new(
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

trait SubscriberWrapper: EventSubscriber {
    fn get_event_fd(&self) -> Result<EventFd>;
}

impl SubscriberWrapper for ApiSeverSubscriber {
    fn get_event_fd(&self) -> Result<EventFd> {
        self.event_fd.try_clone()
    }
}

fn get_default_rlimit_nofile() -> Result<rlim> {
    // Our default RLIMIT_NOFILE target.
    let mut max_fds: rlim = 1_000_000;
    // leave at least this many fds free
    let reserved_fds: rlim = 16_384;

    // Reduce max_fds below the system-wide maximum, if necessary.
    // This ensures there are fds available for other processes so we
    // don't cause resource exhaustion.
    let mut file_max = String::new();
    let mut f = File::open("/proc/sys/fs/file-max")?;
    f.read_to_string(&mut file_max)?;
    let file_max = file_max
        .trim()
        .parse::<rlim>()
        .map_err(|_| Error::InvalidArguments("read fs.file-max sysctl wrong".to_string()))?;
    if file_max < 2 * reserved_fds {
        return Err(io::Error::from(Error::InvalidArguments(
            "The fs.file-max sysctl is too low to allow a reasonable number of open files."
                .to_string(),
        )));
    }

    max_fds = std::cmp::min(file_max - reserved_fds, max_fds);

    Resource::NOFILE
        .get()
        .map(|(curr, _)| if curr >= max_fds { 0 } else { max_fds })
}

struct ApiServer {
    id: String,
    version: String,
}

impl ApiServer {
    fn new(id: String, version: String) -> Result<Self> {
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

extern "C" fn sig_exit(_sig: std::os::raw::c_int) {
    if cfg!(feature = "virtiofsd") {
        // In case of virtiofsd, mechanism to unblock recvmsg() from VMM is lacked.
        // Given the fact that we have nothing to clean up, directly exit seems fine.
        // TODO: But it might be possible to use libc::pthread_kill to unblock it.
        process::exit(0);
    } else {
        // Can't directly exit here since we want to umount rafs reflecting the signal.
        EXIT_EVTFD
            .lock()
            .unwrap()
            .deref()
            .as_ref()
            .unwrap()
            .write(1)
            .unwrap_or_else(|e| error!("Write event fd failed, {}", e))
    }
}

/// Mount Rafs per as to provided mount-info.
fn rafs_mount(info: MountInfo, default_rafs_conf: &RafsConfig, vfs: &Arc<Vfs>) -> Result<()> {
    match info.ops.as_str() {
        "mount" => {
            let mut rafs = match info.config.as_ref() {
                Some(config) => {
                    let content = std::fs::read_to_string(config).map_err(|e| einval!(e))?;
                    let rafs_conf: RafsConfig =
                        serde_json::from_str(&content).map_err(|e| einval!(e))?;
                    Rafs::new(rafs_conf, &info.mountpoint)?
                }
                None => Rafs::new(default_rafs_conf.clone(), &info.mountpoint)?,
            };

            if let Some(source) = info.source.as_ref() {
                let mut file = Box::new(File::open(source).map_err(|e| eother!(e))?)
                    as Box<dyn rafs::RafsIoRead>;
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

fn main() -> Result<()> {
    let cmd_arguments = App::new("vhost-user-fs backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a vhost-user-fs backend.")
        .arg(
            Arg::with_name("bootstrap")
                .long("bootstrap")
                .help("rafs bootstrap file")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("sock")
                .long("sock")
                .help("vhost-user socket path")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("mountpoint")
                .long("mountpoint")
                .help("fuse mount point")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .help("config file")
                .takes_value(true)
                .required(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("apisock")
                .long("apisock")
                .help("admin api socket path")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("shared-dir")
                .long("shared-dir")
                .help("Shared directory path")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .default_value("warn")
                .help("Specify log level: trace, debug, info, warn, error")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("threads")
                .long("thread-num")
                .default_value("1")
                .help("Specify the number of fuse service threads")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("rlimit-nofile")
                .long("rlimit-nofile")
                .default_value("1,000,000")
                .help("set maximum number of file descriptors (0 leaves rlimit unchanged)")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("prefetch-files")
                .long("prefetch-files")
                .help("Specify a files list hinting which files should be prefetched.")
                .takes_value(true)
                .required(false)
                .multiple(true)
                .global(true),
        )
        .get_matches();

    let v = cmd_arguments
        .value_of("log-level")
        .unwrap()
        .parse()
        .unwrap_or(log::LevelFilter::Warn);

    stderrlog::new()
        .quiet(false)
        .verbosity(log_level_to_verbosity(log::LevelFilter::Trace))
        .timestamp(stderrlog::Timestamp::Second)
        .init()
        .unwrap();
    // We rely on `log` macro to limit current log level rather than `stderrlog`
    // So we set stderrlog verbosity to TRACE which is High enough. Otherwise, we
    // can't change log level to a higher level than what is passed to `stderrlog`.
    log::set_max_level(v);
    // A string including multiple directories and regular files should be separated by white-space, e.g.
    //      <path1> <path2> <path3>
    // And each path should be relative to rafs root, e.g.
    //      /foo1/bar1 /foo2/bar2
    // Specifying both regular file and directory are supported.
    let prefetch_files: Vec<&Path>;
    if let Some(files) = cmd_arguments.values_of("prefetch-files") {
        prefetch_files = files.map(|s| Path::new(s)).collect();
        // Sanity check
        for d in &prefetch_files {
            if !d.starts_with(Path::new("/")) {
                return Err(einval!(format!("Illegal prefetch files input {:?}", d)));
            }
        }
    } else {
        prefetch_files = Vec::new();
    }

    // Retrieve arguments
    // sock means vhost-user-backend only
    let vu_sock = cmd_arguments.value_of("sock").unwrap_or_default();
    // mountpoint means fuse device only
    let mountpoint = cmd_arguments.value_of("mountpoint").unwrap_or_default();
    // shared-dir means fs passthrough
    let shared_dir = cmd_arguments.value_of("shared-dir").unwrap_or_default();
    let config = cmd_arguments
        .value_of("config")
        .ok_or_else(|| Error::InvalidArguments("config file is not provided".to_string()))?;
    // bootstrap means rafs only
    let bootstrap = cmd_arguments.value_of("bootstrap").unwrap_or_default();
    // apisock means admin api socket support
    let apisock = cmd_arguments.value_of("apisock").unwrap_or_default();
    // threads means number of fuse service threads
    let threads: u32 = cmd_arguments
        .value_of("threads")
        .map(|n| n.parse().unwrap_or(1))
        .unwrap_or(1);
    let rlimit_nofile_default = get_default_rlimit_nofile()?;
    let rlimit_nofile: rlim = cmd_arguments
        .value_of("rlimit-nofile")
        .map(|n| n.parse().unwrap_or(rlimit_nofile_default))
        .unwrap_or(rlimit_nofile_default);

    // Some basic validation
    if !shared_dir.is_empty() && !bootstrap.is_empty() {
        return Err(einval!(
            "shared-dir and bootstrap cannot be set at the same time"
        ));
    }
    if vu_sock.is_empty() && mountpoint.is_empty() {
        return Err(einval!("either sock or mountpoint must be set".to_string()));
    }
    if !vu_sock.is_empty() && !mountpoint.is_empty() {
        return Err(einval!(
            "sock and mountpoint must not be set at the same time".to_string()
        ));
    }

    let content =
        std::fs::read_to_string(config).map_err(|e| Error::InvalidConfig(e.to_string()))?;
    let rafs_conf: RafsConfig =
        serde_json::from_str(&content).map_err(|e| Error::InvalidConfig(e.to_string()))?;
    let vfs = Vfs::new(VfsOptions::default());
    if !shared_dir.is_empty() {
        // Vfs by default enables no_open and writeback, passthroughfs
        // needs to specify them explicitly.
        // TODO(liubo): enable no_open_dir.
        let fs_cfg = Config {
            root_dir: shared_dir.to_string(),
            do_import: false,
            writeback: true,
            no_open: true,
            ..Default::default()
        };
        let passthrough_fs = PassthroughFs::new(fs_cfg).map_err(Error::FsInitFailure)?;
        passthrough_fs.import()?;
        vfs.mount(Box::new(passthrough_fs), "/")?;
        info!("vfs mounted");

        info!(
            "set rlimit {}, default {}",
            rlimit_nofile, rlimit_nofile_default
        );
        if rlimit_nofile != 0 {
            Resource::NOFILE.set(rlimit_nofile, rlimit_nofile)?;
        }
    } else if !bootstrap.is_empty() {
        let mut rafs = Rafs::new(rafs_conf.clone(), &"/".to_string())?;
        let mut file = Box::new(File::open(bootstrap)?) as Box<dyn rafs::RafsIoRead>;
        rafs.import(&mut file, Some(prefetch_dirs))?;
        info!("rafs mounted: {}", rafs_conf);
        vfs.mount(Box::new(rafs), "/")?;
        info!("vfs mounted");
    }

    let mut event_manager = EventManager::<Arc<dyn SubscriberWrapper>>::new().unwrap();

    let vfs = Arc::new(vfs);
    if apisock != "" {
        let vfs = Arc::clone(&vfs);

        let api_server =
            ApiServer::new("nydusd".to_string(), env!("CARGO_PKG_VERSION").to_string())?;
        let (api_sender, api_receiver) = channel();
        let api_server_subscriber = Arc::new(ApiSeverSubscriber::new(
            vfs,
            rafs_mount,
            api_server,
            api_receiver,
        )?);
        let api_server_id = event_manager.add_subscriber(api_server_subscriber);
        let evtfd = event_manager
            .subscriber_mut(api_server_id)
            .unwrap()
            .get_event_fd()?;
        start_http_thread(apisock, evtfd, api_sender)?;
        info!("api server running at {}", apisock);
    }

    let daemon_subscriber = Arc::new(NydusDaemonSubscriber::new()?);
    let daemon_subscriber_id = event_manager.add_subscriber(daemon_subscriber);
    let evtfd = event_manager
        .subscriber_mut(daemon_subscriber_id)
        .unwrap()
        .get_event_fd()?;
    let exit_evtfd = evtfd.try_clone()?;
    let mut daemon = {
        if !vu_sock.is_empty() {
            create_nydus_daemon(vu_sock, vfs, evtfd, !bootstrap.is_empty())
        } else {
            create_nydus_daemon(mountpoint, vfs, evtfd, !bootstrap.is_empty())
        }
    }?;
    info!("starting fuse daemon");

    *EXIT_EVTFD.lock().unwrap().deref_mut() = Some(exit_evtfd);
    nydus_utils::signal::register_signal_handler(signal::SIGINT, sig_exit);
    nydus_utils::signal::register_signal_handler(signal::SIGTERM, sig_exit);

    if let Err(e) = daemon.start(threads) {
        error!("Failed to start daemon: {:?}", e);
        process::exit(1);
    }

    while EVENT_MANAGER_RUN.load(Ordering::Relaxed) {
        // If event manager dies, so does nydusd
        event_manager.run().unwrap();
    }

    if let Err(e) = daemon.stop() {
        error!("Error shutting down worker thread: {:?}", e)
    }

    if let Err(e) = daemon.wait() {
        error!("Waiting for daemon failed: {:?}", e);
    }

    info!("nydusd quits");
    Ok(())
}
