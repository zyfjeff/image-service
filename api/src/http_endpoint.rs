// Copyright 2020 Ant Financial. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::io;
use std::sync::mpsc::{RecvError, SendError};

use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use serde_json::Error as SerdeError;

use crate::http::{extract_query_part, EndpointHandler};

#[derive(Debug)]
pub enum DaemonErrorKind {
    NotReady,
    UpgradeManager,
    Unsupported,
    Connect(io::Error),
    SendFd,
    RecvFd,
    Disconnect(io::Error),
    Channel,
    Other(String),
}

/// API errors are sent back from the VMM API server through the ApiResponse.
#[derive(Debug)]
pub enum ApiError {
    /// Cannot write to EventFd.
    EventFdWrite(io::Error),

    /// Cannot mount a resource
    MountFailure(DaemonErrorKind),

    /// API request send error
    RequestSend(SendError<ApiRequest>),

    /// Wrong response payload type
    ResponsePayloadType,

    /// API response receive error
    ResponseRecv(RecvError),

    DaemonAbnormal(DaemonErrorKind),

    Metrics(String),
}
pub type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Serialize)]
pub enum ApiResponsePayload {
    /// No data is sent on the channel.
    Empty,
    /// Nydus daemon general working information.
    DaemonInfo(DaemonInfo),
    /// Nydus filesystem global metrics
    FsGlobalMetrics(String),
    /// Nydus filesystem per-file metrics
    FsFilesMetrics(String),
    FsFilesPatterns(String),
}

/// This is the response sent by the API server through the mpsc channel.
pub type ApiResponse = std::result::Result<ApiResponsePayload, ApiError>;
pub type HttpResult = std::result::Result<Response, HttpError>;

//#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ApiRequest {
    DaemonInfo,
    Mount((String, RafsMountInfo)),
    UpdateMount((String, RafsMountInfo)),
    Umount(String),
    ConfigureDaemon(DaemonConf),
    ExportGlobalMetrics(Option<String>),
    ExportFilesMetrics(Option<String>),
    ExportAccessPatterns(Option<String>),
    SendFuseFd,
    Takeover,
    Exit,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct DaemonInfo {
    pub id: Option<String>,
    pub version: String,
    pub supervisor: Option<String>,
    pub state: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct MountInfo {
    /// Bootstrap path by which to import rafs
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub fstype: Option<String>,
    pub mountpoint: String,
    #[serde(default)]
    pub config: Option<String>,
    pub ops: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct RafsMountInfo {
    pub source: String,
    pub config: String,
}

impl RafsMountInfo {
    pub fn parse(body: &Body) -> Result<RafsMountInfo, HttpError> {
        serde_json::from_slice::<RafsMountInfo>(body.raw()).map_err(HttpError::ParseBody)
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct RafsUmountInfo {
    pub mountpoint: String,
}

impl RafsUmountInfo {
    pub fn parse(body: &Body) -> Result<RafsUmountInfo, HttpError> {
        serde_json::from_slice::<RafsUmountInfo>(body.raw()).map_err(HttpError::ParseBody)
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct DaemonConf {
    pub log_level: String,
}

/// Errors associated with Nydus management
#[derive(Debug)]
pub enum HttpError {
    NoRoute,
    BadRequest,
    QueryString(String),
    /// API request receive error
    SerdeJsonDeserialize(SerdeError),
    SerdeJsonSerialize(SerdeError),
    ParseBody(SerdeError),
    /// Could not query daemon info
    Info(ApiError),
    /// Could not mount resource
    Mount(ApiError),
    GlobalMetrics(ApiError),
    FsFilesMetrics(ApiError),
    Pattern(ApiError),
    Configure(ApiError),
    Upgrade(ApiError),
}

fn to_string(d: &impl serde::Serialize) -> Result<String, HttpError> {
    serde_json::to_string(d).map_err(HttpError::SerdeJsonSerialize)
}

fn success_response(body: Option<String>) -> Response {
    let status_code = if body.is_some() {
        StatusCode::OK
    } else {
        StatusCode::NoContent
    };
    let mut r = Response::new(Version::Http11, status_code);
    if let Some(b) = body {
        r.set_body(Body::new(b));
    }
    r
}

#[derive(Serialize, Debug)]
struct ErrorMessage {
    code: String,
    message: String,
}

pub fn error_response(error: HttpError, status: StatusCode) -> Response {
    let mut response = Response::new(Version::Http11, status);

    let err_msg = ErrorMessage {
        code: "UNDEFINED".to_string(),
        message: format!("{:?}", error),
    };
    response.set_body(Body::new(serde_json::to_string(&err_msg).unwrap()));

    response
}

fn translate_status_code(e: &ApiError) -> StatusCode {
    match e {
        ApiError::DaemonAbnormal(kind) | ApiError::MountFailure(kind) => match kind {
            DaemonErrorKind::NotReady => StatusCode::ServiceUnavailable,
            DaemonErrorKind::Unsupported => StatusCode::NotImplemented,
            _ => StatusCode::InternalServerError,
        },
        _ => StatusCode::InternalServerError,
    }
}

fn convert_to_response<O: FnOnce(ApiError) -> HttpError>(
    api_resp: ApiResponse,
    op: O,
) -> Result<Response, HttpError> {
    match api_resp {
        Ok(r) => {
            use ApiResponsePayload::*;
            let resp = match r {
                Empty => success_response(None),
                DaemonInfo(d) => success_response(Some(to_string(&d)?)),
                FsFilesMetrics(d) => success_response(Some(d)),
                FsGlobalMetrics(d) => success_response(Some(d)),
                FsFilesPatterns(d) => success_response(Some(d)),
            };

            Ok(resp)
        }
        Err(e) => {
            let sc = translate_status_code(&e);
            Ok(error_response(op(e), sc))
        }
    }
}

fn parse_configure_daemon_request(body: &Body) -> Result<DaemonConf, HttpError> {
    serde_json::from_slice::<DaemonConf>(body.raw()).map_err(HttpError::ParseBody)
}

pub struct InfoHandler {}
impl EndpointHandler for InfoHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let r = kicker(ApiRequest::DaemonInfo);
                convert_to_response(r, HttpError::Info)
            }
            (Method::Put, Some(body)) => {
                let conf = parse_configure_daemon_request(body)?;
                let r = kicker(ApiRequest::ConfigureDaemon(conf));
                convert_to_response(r, HttpError::Configure)
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MountHandler {}
impl EndpointHandler for MountHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        let mountpoint = extract_query_part(req, "mountpoint").ok_or_else(|| {
            HttpError::QueryString("'mountpoint' should be specified in query string".to_string())
        })?;
        match (req.method(), req.body.as_ref()) {
            (Method::Post, Some(body)) => {
                let info = RafsMountInfo::parse(body)?;
                let r = kicker(ApiRequest::Mount((mountpoint, info)));
                convert_to_response(r, HttpError::Mount)
            }
            (Method::Put, Some(body)) => {
                let info = RafsMountInfo::parse(body)?;
                let r = kicker(ApiRequest::UpdateMount((mountpoint, info)));
                convert_to_response(r, HttpError::Mount)
            }
            (Method::Delete, None) => {
                let r = kicker(ApiRequest::Umount(mountpoint));
                convert_to_response(r, HttpError::Mount)
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MetricsHandler {}
impl EndpointHandler for MetricsHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, &"id");
                let r = kicker(ApiRequest::ExportGlobalMetrics(id));
                convert_to_response(r, HttpError::GlobalMetrics)
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MetricsFilesHandler {}
impl EndpointHandler for MetricsFilesHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, &"id");
                let r = kicker(ApiRequest::ExportFilesMetrics(id));
                convert_to_response(r, HttpError::FsFilesMetrics)
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct MetricsPatternHandler {}
impl EndpointHandler for MetricsPatternHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, &"id");
                let r = kicker(ApiRequest::ExportAccessPatterns(id));
                convert_to_response(r, HttpError::Pattern)
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct SendFuseFdHandler {}
impl EndpointHandler for SendFuseFdHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, None) => {
                let r = kicker(ApiRequest::SendFuseFd);
                convert_to_response(r, HttpError::Upgrade)
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct TakeoverHandler {}
impl EndpointHandler for TakeoverHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, None) => {
                let r = kicker(ApiRequest::Takeover);
                convert_to_response(r, HttpError::Upgrade)
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}

pub struct ExitHandler {}
impl EndpointHandler for ExitHandler {
    fn handle_request(
        &self,
        req: &Request,
        kicker: &dyn Fn(ApiRequest) -> ApiResponse,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, None) => {
                let r = kicker(ApiRequest::Exit);
                convert_to_response(r, HttpError::Upgrade)
            }
            _ => Err(HttpError::BadRequest),
        }
    }
}
