// Copyright 2020 Ant Financial. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use(crate_version, crate_authors)]
extern crate clap;
#[macro_use]
extern crate log;
extern crate config;
extern crate rafs;
extern crate stderrlog;

use std::fs::File;
use std::io::Result;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
#[cfg(feature = "virtiofsd")]
use std::sync::RwLock;
use std::thread;
use std::{convert, error, fmt, io, process};

use libc::EFD_NONBLOCK;

use clap::{App, Arg};
use fuse_rs::api::server::Server;
use fuse_rs::api::{Vfs, VfsOptions};
use fuse_rs::passthrough::{Config, PassthroughFs};
#[cfg(feature = "virtiofsd")]
use fuse_rs::transport::{Error as FuseTransportError, FsCacheReqHandler, Reader, Writer};
use fuse_rs::Error as VhostUserFsError;
#[cfg(feature = "virtiofsd")]
use vhost_rs::vhost_user::message::*;
#[cfg(feature = "virtiofsd")]
use vhost_rs::vhost_user::SlaveFsCacheReq;
#[cfg(feature = "virtiofsd")]
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring};
#[cfg(feature = "virtiofsd")]
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

use nydus_api::http::start_http_thread;
use nydus_api::http_endpoint::{ApiError, ApiRequest, ApiResponsePayload, DaemonInfo, MountInfo};
use nydus_utils::log_level_to_verbosity;
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
        io::Error::new(io::ErrorKind::Other, e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EpollDispatch {
    Exit,
    Reset,
    Stdin,
    Api,
}

pub struct EpollContext {
    raw_fd: RawFd,
    dispatch_table: Vec<Option<EpollDispatch>>,
}

impl EpollContext {
    pub fn new() -> Result<EpollContext> {
        let raw_fd = epoll::create(true)?;

        // Initial capacity needs to be large enough to hold:
        // * 1 exit event
        // * 1 reset event
        // * 1 stdin event
        // * 1 API event
        let mut dispatch_table = Vec::with_capacity(5);
        dispatch_table.push(None);

        Ok(EpollContext {
            raw_fd,
            dispatch_table,
        })
    }

    fn add_event<T>(&mut self, fd: &T, token: EpollDispatch) -> Result<()>
    where
        T: AsRawFd,
    {
        let dispatch_index = self.dispatch_table.len() as u64;
        epoll::ctl(
            self.raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )?;
        self.dispatch_table.push(Some(token));

        Ok(())
    }
}

impl AsRawFd for EpollContext {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd
    }
}

struct ApiServer {
    id: String,
    version: String,
    epoll: EpollContext,
    api_evt: EventFd,
}

impl ApiServer {
    fn new(id: String, version: String, api_evt: EventFd) -> Result<Self> {
        let mut epoll = EpollContext::new().map_err(Error::Epoll)?;
        epoll
            .add_event(&api_evt, EpollDispatch::Api)
            .map_err(Error::Epoll)?;

        Ok(ApiServer {
            id,
            version,
            epoll,
            api_evt,
        })
    }

    // control loop to handle api requests
    fn control_loop<FF>(&self, api_receiver: Receiver<ApiRequest>, mut mounter: FF) -> Result<()>
    where
        FF: FnMut(MountInfo) -> std::result::Result<ApiResponsePayload, ApiError>,
    {
        const EPOLL_EVENTS_LEN: usize = 100;

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];
        let epoll_fd = self.epoll.as_raw_fd();

        trace!("api control loop start");
        loop {
            let num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(e);
                }
            };

            trace!("receive api control {} events", num_events);

            for event in events.iter().take(num_events) {
                let dispatch_idx = event.data as usize;

                if let Some(dispatch_type) = self.epoll.dispatch_table[dispatch_idx] {
                    match dispatch_type {
                        EpollDispatch::Api => {
                            // Consume the event.
                            self.api_evt.read()?;

                            // Read from the API receiver channel
                            let api_request = api_receiver.recv().map_err(|e| {
                                error!("receive API channel failed {}", e);
                                io::Error::from(io::ErrorKind::BrokenPipe)
                            })?;

                            match api_request {
                                ApiRequest::DaemonInfo(sender) => {
                                    let response = DaemonInfo {
                                        id: self.id.to_string(),
                                        version: self.version.to_string(),
                                        state: "Running".to_string(),
                                    };

                                    sender
                                        .send(Ok(response).map(ApiResponsePayload::DaemonInfo))
                                        .map_err(|e| {
                                            error!("send API response failed {}", e);
                                            io::Error::from(io::ErrorKind::BrokenPipe)
                                        })?;
                                }
                                ApiRequest::Mount(info, sender) => {
                                    sender.send(mounter(info)).map_err(|e| {
                                        error!("send API response failed {}", e);
                                        io::Error::from(io::ErrorKind::BrokenPipe)
                                    })?;
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
                                    if let Err(e) =
                                        sender.send(Ok(ApiResponsePayload::FsGlobalMetrics(resp)))
                                    {
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
                                    if let Err(e) =
                                        sender.send(Ok(ApiResponsePayload::FsFilesMetrics(resp)))
                                    {
                                        error!("send API response failed {}", e);
                                    }
                                }
                            }
                        }
                        t => {
                            error!("unexpected event type {:?}", t);
                        }
                    }
                }
            }
        }
    }
}

// Start the api server and kick of a local thread to handle
// api requests.
fn start_api_server<FF>(
    id: String,
    version: String,
    http_path: String,
    mounter: FF,
) -> Result<thread::JoinHandle<Result<()>>>
where
    FF: Send + Sync + 'static + Fn(MountInfo) -> std::result::Result<ApiResponsePayload, ApiError>,
{
    let api_evt = EventFd::new(EFD_NONBLOCK).map_err(Error::Epoll)?;
    let http_api_event = api_evt.try_clone().map_err(Error::EventFdClone)?;
    let (api_sender, api_receiver) = channel();

    let thread = thread::Builder::new()
        .name("api_handler".to_string())
        .spawn(move || {
            let s = ApiServer::new(id, version, api_evt)?;
            s.control_loop(api_receiver, mounter)
        })
        .map_err(Error::ThreadSpawn)?;

    // The VMM thread is started, we can start serving HTTP requests
    start_http_thread(&http_path, http_api_event, api_sender)?;

    Ok(thread)
}

trait NydusDaemon {
    fn start(&mut self, cnt: u32) -> Result<()>;
    fn wait(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
}

#[allow(dead_code)]
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
impl VhostUserFsBackend {
    fn new(vfs: Arc<Vfs>) -> Result<Self> {
        Ok(VhostUserFsBackend {
            mem: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::Epoll)?,
            server: Arc::new(Server::new(vfs)),
            vu_req: None,
            used_descs: Vec::with_capacity(QUEUE_SIZE),
        })
    }

    // There's no way to recover if error happens during processing a virtq, let the caller
    // to handle it.
    fn process_queue(&mut self, vring: &mut Vring) -> Result<()> {
        let mem = self.mem.as_ref().ok_or(Error::NoMemoryConfigured)?;

        while let Some(avail_desc) = vring.mut_queue().iter(mem).next() {
            let head_index = avail_desc.index;
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
impl VhostUserBackend for VhostUserFsBackend {
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
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        index: u16,
        evset: epoll::Events,
        vrings: &[Arc<RwLock<Vring>>],
    ) -> VhostUserBackendResult<bool> {
        if evset != epoll::Events::EPOLLIN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match index {
            HIPRIO_QUEUE_EVENT => {
                let mut vring = vrings[HIPRIO_QUEUE_EVENT as usize].write().unwrap();
                // high priority requests are also just plain fuse requests, just in a
                // different queue
                self.process_queue(&mut vring)?;
            }
            x if x >= REQ_QUEUE_EVENT && x < vrings.len() as u16 => {
                let mut vring = vrings[x as usize].write().unwrap();
                self.process_queue(&mut vring)?;
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        }

        Ok(false)
    }

    fn exit_event(&self) -> Option<(EventFd, Option<u16>)> {
        Some((self.kill_evt.try_clone().unwrap(), Some(KILL_EVENT)))
    }

    fn set_slave_req_fd(&mut self, vu_req: SlaveFsCacheReq) {
        self.vu_req = Some(vu_req);
    }
}

#[cfg(feature = "virtiofsd")]
impl<S: VhostUserBackend> NydusDaemon for VhostUserDaemon<S> {
    fn start(&mut self, _: u32) -> Result<()> {
        self.start()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
    }

    fn wait(&mut self) -> Result<()> {
        self.wait()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
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
fn create_nydus_daemon(sock: &str, fs: Arc<Vfs>) -> Result<Box<dyn NydusDaemon>> {
    let daemon = VhostUserDaemon::new(
        String::from("vhost-user-fs-backend"),
        String::from(sock),
        Arc::new(RwLock::new(VhostUserFsBackend::new(fs)?)),
    )
    .map_err(|e| Error::DaemonFailure(format!("{:?}", e)))?;
    Ok(Box::new(daemon))
}

#[cfg(feature = "fusedev")]
struct FuseServer {
    server: Arc<Server<Arc<Vfs>>>,
    ch: FuseChannel,
    // read buffer for fuse requests
    buf: Vec<u8>,
}

#[cfg(feature = "fusedev")]
impl FuseServer {
    fn new(server: Arc<Server<Arc<Vfs>>>, se: &FuseSession) -> Result<FuseServer> {
        Ok(FuseServer {
            server,
            ch: se.new_channel(),
            buf: Vec::with_capacity(se.bufsize()),
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
        Ok(())
    }
}

#[cfg(feature = "fusedev")]
struct FusedevDaemon {
    server: Arc<Server<Arc<Vfs>>>,
    session: FuseSession,
    threads: Vec<Option<thread::JoinHandle<Result<()>>>>,
}

#[cfg(feature = "fusedev")]
impl FusedevDaemon {
    fn kick_one_server(&mut self) -> Result<()> {
        let mut s = FuseServer::new(self.server.clone(), &self.session)?;

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
        Ok(())
    }
}

#[cfg(feature = "fusedev")]
fn create_nydus_daemon(mountpoint: &str, fs: Arc<Vfs>) -> Result<Box<dyn NydusDaemon>> {
    Ok(Box::new(FusedevDaemon {
        session: FuseSession::new(Path::new(mountpoint), "nydusfs", "")?,
        server: Arc::new(Server::new(fs)),
        threads: Vec::new(),
    }))
}

fn main() -> Result<()> {
    let cmd_arguments = App::new("vhost-user-fs backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a vhost-user-fs backend.")
        .arg(
            Arg::with_name("metadata")
                .long("metadata")
                .help("rafs metadata file")
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
    // metadata means rafs only
    let metadata = cmd_arguments.value_of("metadata").unwrap_or_default();
    // apisock means admin api socket support
    let apisock = cmd_arguments.value_of("apisock").unwrap_or_default();
    // threads means number of fuse service threads
    let threads: u32 = cmd_arguments
        .value_of("threads")
        .map(|n| n.parse().unwrap_or(1))
        .unwrap_or(1);

    // Some basic validation
    if !shared_dir.is_empty() && !metadata.is_empty() {
        return Err(io::Error::from(Error::InvalidArguments(
            "shared-dir and metadata cannot be set at the same time".to_string(),
        )));
    }
    if vu_sock.is_empty() && mountpoint.is_empty() {
        return Err(io::Error::from(Error::InvalidArguments(
            "either sock or mountpoint must be set".to_string(),
        )));
    }
    if !vu_sock.is_empty() && !mountpoint.is_empty() {
        return Err(io::Error::from(Error::InvalidArguments(
            "sock and mountpoint must not be set at the same time".to_string(),
        )));
    }

    let mut settings = config::Config::new();
    settings
        .merge(config::File::from(Path::new(config)))
        .map_err(|e| Error::InvalidConfig(e.to_string()))?;
    let rafs_conf: RafsConfig = settings
        .try_into()
        .map_err(|e| Error::InvalidConfig(e.to_string()))?;

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
    } else if !metadata.is_empty() {
        let mut rafs = Rafs::new(rafs_conf.clone(), &"/".to_string())?;
        let mut file = Box::new(File::open(metadata)?) as Box<dyn rafs::RafsIoRead>;
        rafs.import(&mut file)?;
        info!("rafs mounted");
        vfs.mount(Box::new(rafs), "/")?;
        info!("vfs mounted");
    }

    let vfs = Arc::new(vfs);
    if apisock != "" {
        let vfs = Arc::clone(&vfs);
        start_api_server(
            "nydusd".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
            apisock.to_string(),
            move |info| {
                let mut rafs = match info.config.as_ref() {
                    Some(config) => {
                        let mut settings = config::Config::new();
                        settings
                            .merge(config::File::from(Path::new(config)))
                            .map_err(|e| {
                                ApiError::MountFailure(io::Error::new(
                                    io::ErrorKind::Other,
                                    e.to_string(),
                                ))
                            })?;

                        let rafs_conf: RafsConfig = settings.try_into().map_err(|e| {
                            ApiError::MountFailure(io::Error::new(
                                io::ErrorKind::Other,
                                e.to_string(),
                            ))
                        })?;

                        Rafs::new(rafs_conf, &info.mountpoint).map_err(|e| {
                            ApiError::MountFailure(io::Error::new(
                                io::ErrorKind::Other,
                                e.to_string(),
                            ))
                        })?
                    }
                    None => Rafs::new(rafs_conf.clone(), &info.mountpoint).map_err(|e| {
                        ApiError::MountFailure(io::Error::new(io::ErrorKind::Other, e.to_string()))
                    })?,
                };
                let mut file = Box::new(File::open(&info.source).map_err(ApiError::MountFailure)?)
                    as Box<dyn rafs::RafsIoRead>;
                rafs.import(&mut file).map_err(ApiError::MountFailure)?;
                info!("rafs mounted");

                match vfs.mount(Box::new(rafs), &info.mountpoint) {
                    Ok(()) => Ok(ApiResponsePayload::Mount),
                    Err(e) => {
                        error!("mount {:?} failed {}", info, e);
                        Err(ApiError::MountFailure(io::Error::from(
                            io::ErrorKind::InvalidData,
                        )))
                    }
                }
            },
        )?;
        info!("api server running at {}", apisock);
    }

    let mut daemon = {
        if !vu_sock.is_empty() {
            create_nydus_daemon(vu_sock, vfs)
        } else {
            create_nydus_daemon(mountpoint, vfs)
        }
    }?;
    info!("starting fuse daemon");
    if let Err(e) = daemon.start(threads) {
        error!("Failed to start daemon: {:?}", e);
        process::exit(1);
    }

    if let Err(e) = daemon.wait() {
        error!("Waiting for daemon failed: {:?}", e);
    }

    if let Err(e) = daemon.stop() {
        error!("Error shutting down worker thread: {:?}", e)
    }

    info!("nydusd quits");
    Ok(())
}
