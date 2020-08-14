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

#[cfg(feature = "virtiofsd")]
use libc::EFD_NONBLOCK;
use std::fs::File;
use std::io::{Read, Result};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
#[cfg(feature = "virtiofsd")]
use std::sync::RwLock;
use std::sync::{Arc, Mutex};
#[cfg(feature = "fusedev")]
use std::thread;
use std::{convert, error, fmt, io, process};

use nix::sys::signal;
use rlimit::{rlim, Resource};

use clap::{App, Arg};
use fuse_rs::api::server::Server;
use fuse_rs::api::{Vfs, VfsOptions};
use fuse_rs::passthrough::{Config, PassthroughFs};
#[cfg(feature = "virtiofsd")]
use fuse_rs::transport::{Error as FuseTransportError, FsCacheReqHandler, Reader, Writer};
use fuse_rs::Error as VhostUserFsError;
#[cfg(feature = "fusedev")]
use std::path::Path;
#[cfg(feature = "virtiofsd")]
use vhost_rs::vhost_user::message::*;
#[cfg(feature = "virtiofsd")]
use vhost_rs::vhost_user::{Listener, SlaveFsCacheReq};
#[cfg(feature = "virtiofsd")]
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring};
#[cfg(feature = "virtiofsd")]
use vm_memory::GuestMemoryMmap;

use nydus_api::http::start_http_thread;
use nydus_api::http_endpoint::{ApiError, ApiRequest, ApiResponsePayload, DaemonInfo, MountInfo};
use nydus_utils::{einval, enoent, eother, epipe, last_error, log_level_to_verbosity};
#[cfg(feature = "fusedev")]
use nydus_utils::{FuseChannel, FuseSession};
use rafs::fs::{Rafs, RafsConfig};
use rafs::io_stats;

#[cfg(feature = "virtiofsd")]
const VIRTIO_F_VERSION_1: u32 = 32;
#[cfg(feature = "virtiofsd")]
const QUEUE_SIZE: usize = 1024;
#[cfg(feature = "virtiofsd")]
const NUM_QUEUES: usize = 2;

// The guest queued an available buffer for the high priority queue.
#[cfg(feature = "virtiofsd")]
const HIPRIO_QUEUE_EVENT: u16 = 0;
// The guest queued an available buffer for the request queue.
#[cfg(feature = "virtiofsd")]
const REQ_QUEUE_EVENT: u16 = 1;
// The device has been dropped.
#[cfg(feature = "virtiofsd")]
const KILL_EVENT: u16 = 2;

/// TODO: group virtiofsd code into a different file
#[cfg(feature = "virtiofsd")]
type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[allow(dead_code)]
#[derive(Debug)]
enum Error {
    /// Invalid arguments provided.
    InvalidArguments(String),
    /// Invalid config provided
    InvalidConfig(String),
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// No memory configured.
    NoMemoryConfigured,
    /// Invalid Virtio descriptor chain.
    #[cfg(feature = "virtiofsd")]
    InvalidDescriptorChain(FuseTransportError),
    /// Processing queue failed.
    ProcessQueue(VhostUserFsError),
    /// Cannot create epoll context.
    Epoll(io::Error),
    /// Cannot clone event fd.
    EventFdClone(io::Error),
    /// Cannot spawn a new thread
    ThreadSpawn(io::Error),
    /// Failure to initialize file system
    FsInitFailure(io::Error),
    /// Daemon related error
    DaemonFailure(String),
    /// Wait daemon failure
    WaitDaemon,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidArguments(s) => write!(f, "Invalid argument: {}", s),
            Error::InvalidConfig(s) => write!(f, "Invalid config: {}", s),
            Error::DaemonFailure(s) => write!(f, "Daemon error: {}", s),
            _ => write!(f, "vhost_user_fs_error: {:?}", self),
        }
    }
}

impl error::Error for Error {}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        einval!(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EpollDispatch {
    Exit,
    Reset,
    Stdin,
    Api,
}

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

trait NydusDaemon {
    fn start(&mut self, cnt: u32) -> Result<()>;
    fn wait(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
}

#[allow(dead_code)]
#[cfg(feature = "virtiofsd")]
struct VhostUserFsBackendHandler {
    backend: Mutex<VhostUserFsBackend>,
}

#[cfg(feature = "virtiofsd")]
struct VhostUserFsBackend {
    mem: Option<GuestMemoryMmap>,
    kill_evt: EventFd,
    server: Arc<Server<Arc<Vfs>>>,
    // handle request from slave to master
    vu_req: Option<SlaveFsCacheReq>,
    used_descs: Vec<(u16, u32)>,
}

#[cfg(feature = "virtiofsd")]
impl VhostUserFsBackendHandler {
    fn new(vfs: Arc<Vfs>) -> Result<Self> {
        let backend = VhostUserFsBackend {
            mem: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::Epoll)?,
            server: Arc::new(Server::new(vfs)),
            vu_req: None,
            used_descs: Vec::with_capacity(QUEUE_SIZE),
        };
        Ok(VhostUserFsBackendHandler {
            backend: Mutex::new(backend),
        })
    }
}

#[cfg(feature = "virtiofsd")]
impl VhostUserFsBackend {
    // There's no way to recover if error happens during processing a virtq, let the caller
    // to handle it.
    fn process_queue(&mut self, vring: &mut Vring) -> Result<()> {
        let mem = self.mem.as_ref().ok_or(Error::NoMemoryConfigured)?;

        while let Some(avail_desc) = vring.mut_queue().iter(mem).next() {
            let head_index = avail_desc.index();
            let reader =
                Reader::new(mem, avail_desc.clone()).map_err(Error::InvalidDescriptorChain)?;
            let writer = Writer::new(mem, avail_desc).map_err(Error::InvalidDescriptorChain)?;

            let total = self
                .server
                .handle_message(
                    reader,
                    writer,
                    self.vu_req
                        .as_mut()
                        .map(|x| x as &mut dyn FsCacheReqHandler),
                )
                .map_err(Error::ProcessQueue)?;

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

#[cfg(feature = "virtiofsd")]
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
            return Err(Error::HandleEventNotEpollIn.into());
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
            _ => return Err(Error::HandleEventUnknownEvent.into()),
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

#[cfg(feature = "virtiofsd")]
struct VirtiofsDaemon<S: VhostUserBackend> {
    sock: String,
    daemon: VhostUserDaemon<S>,
}

#[cfg(feature = "virtiofsd")]
impl<S: VhostUserBackend> NydusDaemon for VirtiofsDaemon<S> {
    fn start(&mut self, _: u32) -> Result<()> {
        let listener = Listener::new(&self.sock, true).unwrap();
        self.daemon.start(listener).map_err(|e| einval!(e))
    }

    fn wait(&mut self) -> Result<()> {
        self.daemon.wait().map_err(|e| einval!(e))
    }

    fn stop(&mut self) -> Result<()> {
        /* TODO: find a way to kill backend
        let kill_evt = &backend.read().unwrap().kill_evt;
        if let Err(e) = kill_evt.write(1) {}
        */
        Ok(())
    }
}

#[cfg(feature = "virtiofsd")]
fn create_nydus_daemon(
    sock: &str,
    fs: Arc<Vfs>,
    _evtfd: EventFd,
    _readonly: bool,
) -> Result<Box<dyn NydusDaemon>> {
    let daemon = VhostUserDaemon::new(
        String::from("vhost-user-fs-backend"),
        Arc::new(RwLock::new(VhostUserFsBackendHandler::new(fs)?)),
    )
    .map_err(|e| Error::DaemonFailure(format!("{:?}", e)))?;
    Ok(Box::new(VirtiofsDaemon {
        sock: sock.to_owned(),
        daemon,
    }))
}

#[cfg(feature = "fusedev")]
struct FuseServer {
    server: Arc<Server<Arc<Vfs>>>,
    ch: FuseChannel,
    // read buffer for fuse requests
    buf: Vec<u8>,
    evtfd: EventFd,
}

#[cfg(feature = "fusedev")]
impl FuseServer {
    fn new(server: Arc<Server<Arc<Vfs>>>, se: &FuseSession, evtfd: EventFd) -> Result<FuseServer> {
        Ok(FuseServer {
            server,
            ch: se.new_channel()?,
            buf: Vec::with_capacity(se.bufsize()),
            evtfd,
        })
    }

    fn svc_loop(&mut self) -> Result<()> {
        // Safe because we have already reserved the capacity
        unsafe {
            self.buf.set_len(self.buf.capacity());
        }
        loop {
            if let Some(reader) = self.ch.get_reader(&mut self.buf)? {
                let writer = self.ch.get_writer()?;
                self.server
                    .handle_message(reader, writer, None)
                    .map_err(|e| {
                        error! {"handle message failed: {}", e};
                        Error::ProcessQueue(e)
                    })?;
            } else {
                info!("fuse server exits");
                break;
            }
        }
        EVENT_MANAGER_RUN.store(false, Ordering::Relaxed);
        self.evtfd.write(1).unwrap();
        Ok(())
    }
}

#[cfg(feature = "fusedev")]
struct FusedevDaemon {
    server: Arc<Server<Arc<Vfs>>>,
    session: FuseSession,
    threads: Vec<Option<thread::JoinHandle<Result<()>>>>,
    event_fd: EventFd,
}

#[cfg(feature = "fusedev")]
impl FusedevDaemon {
    fn kick_one_server(&mut self) -> Result<()> {
        let mut s = FuseServer::new(
            self.server.clone(),
            &self.session,
            // Clone event fd must succeed, otherwise fusedev daemon should not work.
            self.event_fd.try_clone().unwrap(),
        )?;

        let thread = thread::Builder::new()
            .name("fuse_server".to_string())
            .spawn(move || s.svc_loop())
            .map_err(Error::ThreadSpawn)?;
        self.threads.push(Some(thread));
        Ok(())
    }
}

#[cfg(feature = "fusedev")]
impl NydusDaemon for FusedevDaemon {
    fn start(&mut self, cnt: u32) -> Result<()> {
        for _ in 0..cnt {
            self.kick_one_server()?;
        }
        Ok(())
    }

    fn wait(&mut self) -> Result<()> {
        for t in &mut self.threads {
            if let Some(handle) = t.take() {
                handle.join().map_err(|_| Error::WaitDaemon)??;
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.session.umount()
    }
}

#[cfg(feature = "fusedev")]
fn create_nydus_daemon(
    mountpoint: &str,
    fs: Arc<Vfs>,
    evtfd: EventFd,
    readonly: bool,
) -> Result<Box<dyn NydusDaemon>> {
    Ok(Box::new(FusedevDaemon {
        session: FuseSession::new(Path::new(mountpoint), "nydusfs", "", readonly)?,
        server: Arc::new(Server::new(fs)),
        threads: Vec::new(),
        event_fd: evtfd,
    }))
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
                rafs.import(&mut file)?;

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
        .get_matches();

    let v = cmd_arguments
        .value_of("log-level")
        .unwrap()
        .parse()
        .unwrap_or(log::LevelFilter::Warn);

    stderrlog::new()
        .quiet(false)
        .verbosity(log_level_to_verbosity(v))
        .timestamp(stderrlog::Timestamp::Second)
        .init()
        .unwrap();

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
        rafs.import(&mut file)?;
        info!("rafs mounted: {}", rafs_conf);
        vfs.mount(Box::new(rafs), "/")?;
        info!("vfs mounted");
    }

    nydus_utils::signal::register_signal_handler(signal::SIGINT, sig_exit);
    nydus_utils::signal::register_signal_handler(signal::SIGTERM, sig_exit);

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
