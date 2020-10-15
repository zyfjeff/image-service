// Copyright 2020 Ant Financial. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::mpsc::{Receiver, RecvError, SendError, Sender};

use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use serde_json::Error as SerdeError;
use vmm_sys_util::eventfd::EventFd;

use crate::http::{extract_query_part, EndpointHandler};

#[derive(Debug)]
pub enum DaemonErrorKind {
    NotReady,
    NoResource,
    Connect(io::Error),
    SendFd,
    RecvFd,
    Disconnect(io::Error),
    Channel,
    Other,
}

/// API errors are sent back from the VMM API server through the ApiResponse.
#[derive(Debug)]
pub enum ApiError {
    /// Cannot write to EventFd.
    EventFdWrite(io::Error),

    /// Cannot mount a resource
    MountFailure(io::Error),

    /// API request send error
    RequestSend(SendError<ApiRequest>),

    /// Wrong response payload type
    ResponsePayloadType,

    /// API response receive error
    ResponseRecv(RecvError),

    DaemonAbnormal(DaemonErrorKind),
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
    Mount(MountInfo),
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

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct MountInfo {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub fstype: Option<String>,
    pub mountpoint: String,
    #[serde(default)]
    pub config: Option<String>,
    pub ops: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct DaemonConf {
    pub log_level: String,
}

/// Errors associated with Nydus management
#[derive(Debug)]
pub enum HttpError {
    /// API request receive error
    SerdeJsonDeserialize(SerdeError),
    SerdeJsonSerialize(SerdeError),
    ParseBody,
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

fn kick_api_server(
    api_evt: EventFd,
    to_api: Sender<ApiRequest>,
    from_api: &Receiver<ApiResponse>,
    request: ApiRequest,
) -> ApiResponse {
    to_api.send(request).map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;
    from_api.recv().map_err(ApiError::ResponseRecv)?
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

fn error_response(error: Option<HttpError>, status: StatusCode) -> Response {
    let mut response = Response::new(Version::Http11, status);

    if let Some(e) = error {
        response.set_body(Body::new(format!("{:?}", e)));
    }
    response
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
                FsFilesMetrics(d) => success_response(Some(to_string(&d)?)),
                FsGlobalMetrics(d) => success_response(Some(to_string(&d)?)),
                FsFilesPatterns(d) => success_response(Some(to_string(&d)?)),
            };

            Ok(resp)
        }
        Err(e) => Ok(error_response(Some(op(e)), StatusCode::InternalServerError)),
    }
}

fn parse_mount_request(body: &Body) -> Result<MountInfo, HttpError> {
    serde_json::from_slice::<MountInfo>(body.raw()).map_err(|_| HttpError::ParseBody)
}

fn parse_configure_daemon_request(body: &Body) -> Result<DaemonConf, HttpError> {
    serde_json::from_slice::<DaemonConf>(body.raw()).map_err(|_| HttpError::ParseBody)
}

pub struct InfoHandler {}
impl EndpointHandler for InfoHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        to_api: Sender<ApiRequest>,
        from_api: &Receiver<ApiResponse>,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let r = kick_api_server(api_notifier, to_api, from_api, ApiRequest::DaemonInfo);
                convert_to_response(r, HttpError::Info)
            }
            (Method::Put, Some(body)) => {
                let conf = parse_configure_daemon_request(body)?;
                let r = kick_api_server(
                    api_notifier,
                    to_api,
                    from_api,
                    ApiRequest::ConfigureDaemon(conf),
                );
                convert_to_response(r, HttpError::Configure)
            }
            _ => Ok(error_response(None, StatusCode::BadRequest)),
        }
    }
}

pub struct MountHandler {}
impl EndpointHandler for MountHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        to_api: Sender<ApiRequest>,
        from_api: &Receiver<ApiResponse>,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, Some(body)) => {
                let info = parse_mount_request(body)?;
                let r = kick_api_server(api_notifier, to_api, from_api, ApiRequest::Mount(info));
                convert_to_response(r, HttpError::Mount)
            }
            _ => Ok(error_response(None, StatusCode::BadRequest)),
        }
    }
}

pub struct MetricsHandler {}
impl EndpointHandler for MetricsHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        to_api: Sender<ApiRequest>,
        from_api: &Receiver<ApiResponse>,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, &"id");
                let r = kick_api_server(
                    api_notifier,
                    to_api,
                    from_api,
                    ApiRequest::ExportGlobalMetrics(id),
                );
                convert_to_response(r, HttpError::GlobalMetrics)
            }
            _ => Ok(error_response(None, StatusCode::BadRequest)),
        }
    }
}

pub struct MetricsFilesHandler {}
impl EndpointHandler for MetricsFilesHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        to_api: Sender<ApiRequest>,
        from_api: &Receiver<ApiResponse>,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, &"id");
                let r = kick_api_server(
                    api_notifier,
                    to_api,
                    from_api,
                    ApiRequest::ExportFilesMetrics(id),
                );
                convert_to_response(r, HttpError::FsFilesMetrics)
            }
            _ => Ok(error_response(None, StatusCode::BadRequest)),
        }
    }
}

pub struct MetricsPatternHandler {}
impl EndpointHandler for MetricsPatternHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        to_api: Sender<ApiRequest>,
        from_api: &Receiver<ApiResponse>,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Get, None) => {
                let id = extract_query_part(req, &"id");
                let r = kick_api_server(
                    api_notifier,
                    to_api,
                    from_api,
                    ApiRequest::ExportAccessPatterns(id),
                );
                convert_to_response(r, HttpError::Pattern)
            }
            _ => Ok(error_response(None, StatusCode::BadRequest)),
        }
    }
}

pub struct SendFuseFdHandler {}
impl EndpointHandler for SendFuseFdHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        to_api: Sender<ApiRequest>,
        from_api: &Receiver<ApiResponse>,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, None) => {
                let r = kick_api_server(api_notifier, to_api, from_api, ApiRequest::SendFuseFd);
                convert_to_response(r, HttpError::Upgrade)
            }
            _ => Ok(error_response(None, StatusCode::BadRequest)),
        }
    }
}

pub struct TakeoverHandler {}
impl EndpointHandler for TakeoverHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        to_api: Sender<ApiRequest>,
        from_api: &Receiver<ApiResponse>,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, None) => {
                let r = kick_api_server(api_notifier, to_api, from_api, ApiRequest::Takeover);
                convert_to_response(r, HttpError::Upgrade)
            }
            _ => Ok(error_response(None, StatusCode::BadRequest)),
        }
    }
}

pub struct ExitHandler {}
impl EndpointHandler for ExitHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        to_api: Sender<ApiRequest>,
        from_api: &Receiver<ApiResponse>,
    ) -> HttpResult {
        match (req.method(), req.body.as_ref()) {
            (Method::Put, None) => {
                let r = kick_api_server(api_notifier, to_api, from_api, ApiRequest::Exit);
                convert_to_response(r, HttpError::Upgrade)
            }
            _ => Ok(error_response(None, StatusCode::BadRequest)),
        }
    }
}
