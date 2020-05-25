// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io;
use std::sync::mpsc::{channel, RecvError, SendError, Sender};

use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use serde_json::Error as SerdeError;
use vmm_sys_util::eventfd::EventFd;

use crate::http::EndpointHandler;

/// API errors are sent back from the VMM API server through the ApiResponse.
#[derive(Debug)]
pub enum ApiError {
    /// Cannot write to EventFd.
    EventFdWrite(io::Error),

    /// Cannot mount a resource
    MountFailure(io::Error),

    /// API request send error
    RequestSend(SendError<ApiRequest>),

    /// Wrong reponse payload type
    ResponsePayloadType,

    /// API response receive error
    ResponseRecv(RecvError),
}
pub type ApiResult<T> = std::result::Result<T, ApiError>;

pub enum ApiResponsePayload {
    /// No data is sent on the channel.
    Empty,

    /// Virtual machine information
    DaemonInfo(DaemonInfo),

    /// Vmm ping response
    Mount,

    /// Nydus filesystem global metrics
    FsGlobalMetrics(String),

    /// Nydus filesystem per-file metrics
    FsFilesMetrics(String),
}

/// This is the response sent by the API server through the mpsc channel.
pub type ApiResponse = std::result::Result<ApiResponsePayload, ApiError>;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ApiRequest {
    DaemonInfo(Sender<ApiResponse>),
    Mount(MountInfo, Sender<ApiResponse>),
    ConfigureDaemon(DaemonConf, Sender<ApiResponse>),
    ExportGlobalMetrics(Sender<ApiResponse>),
    ExportFilesMetrics(Sender<ApiResponse>),
}

#[derive(Clone, Deserialize, Serialize)]
pub struct DaemonInfo {
    pub id: String,
    pub version: String,
    pub state: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct MountInfo {
    pub source: String,
    pub fstype: String,
    pub mountpoint: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct DaemonConf {
    pub log_level: String,
}

pub fn daemon_info(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<DaemonInfo> {
    let (response_sender, response_receiver) = channel();

    // Send the VM request.
    api_sender
        .send(ApiRequest::DaemonInfo(response_sender))
        .map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;

    let info = response_receiver.recv().map_err(ApiError::ResponseRecv)??;

    match info {
        ApiResponsePayload::DaemonInfo(info) => Ok(info),
        _ => Err(ApiError::ResponsePayloadType),
    }
}

pub fn daemon_configure(
    api_evt: EventFd,
    api_sender: Sender<ApiRequest>,
    conf: DaemonConf,
) -> ApiResult<()> {
    let (response_sender, response_receiver) = channel();

    api_sender
        .send(ApiRequest::ConfigureDaemon(conf, response_sender))
        .map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;

    let info = response_receiver.recv().map_err(ApiError::ResponseRecv)??;

    match info {
        ApiResponsePayload::Empty => Ok(()),
        _ => Err(ApiError::ResponsePayloadType),
    }
}

pub fn mount_info(
    api_evt: EventFd,
    api_sender: Sender<ApiRequest>,
    info: MountInfo,
) -> ApiResult<()> {
    let (response_sender, response_receiver) = channel();

    // Send the VM request.
    api_sender
        .send(ApiRequest::Mount(info, response_sender))
        .map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;

    let info = response_receiver.recv().map_err(ApiError::ResponseRecv)??;

    match info {
        ApiResponsePayload::Mount => Ok(()),
        _ => Err(ApiError::ResponsePayloadType),
    }
}

pub fn export_global_stats(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<String> {
    let (response_sender, response_receiver) = channel();

    api_sender
        .send(ApiRequest::ExportGlobalMetrics(response_sender))
        .map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;

    let info = response_receiver.recv().map_err(ApiError::ResponseRecv)??;

    match info {
        ApiResponsePayload::FsGlobalMetrics(info) => Ok(info),
        _ => Err(ApiError::ResponsePayloadType),
    }
}

pub fn export_files_stats(api_evt: EventFd, api_sender: Sender<ApiRequest>) -> ApiResult<String> {
    let (response_sender, response_receiver) = channel();

    api_sender
        .send(ApiRequest::ExportFilesMetrics(response_sender))
        .map_err(ApiError::RequestSend)?;
    api_evt.write(1).map_err(ApiError::EventFdWrite)?;

    let info = response_receiver.recv().map_err(ApiError::ResponseRecv)??;

    match info {
        ApiResponsePayload::FsFilesMetrics(info) => Ok(info),
        _ => Err(ApiError::ResponsePayloadType),
    }
}

/// Errors associated with VMM management
#[derive(Debug)]
pub enum HttpError {
    /// API request receive error
    SerdeJsonDeserialize(SerdeError),

    /// Could not query daemon info
    Info(ApiError),

    /// Could not mount resource
    Mount(ApiError),
    Configure(ApiError),
}

fn error_response(error: HttpError, status: StatusCode) -> Response {
    let mut response = Response::new(Version::Http11, status);
    response.set_body(Body::new(format!("{:?}", error)));

    response
}

// /api/v1/info handler
pub struct InfoHandler {}

impl EndpointHandler for InfoHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Get => match daemon_info(api_notifier, api_sender).map_err(HttpError::Info) {
                Ok(info) => {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    let info_serialized = serde_json::to_string(&info).unwrap();

                    response.set_body(Body::new(info_serialized));
                    response
                }
                Err(e) => error_response(e, StatusCode::InternalServerError),
            },
            Method::Put => match &req.body {
                Some(body) => {
                    let kv: DaemonConf = match serde_json::from_slice(body.raw())
                        .map_err(HttpError::SerdeJsonDeserialize)
                    {
                        Ok(config) => config,
                        Err(e) => return error_response(e, StatusCode::BadRequest),
                    };

                    match daemon_configure(api_notifier, api_sender, kv)
                        .map_err(HttpError::Configure)
                    {
                        Ok(()) => Response::new(Version::Http11, StatusCode::NoContent),
                        Err(e) => error_response(e, StatusCode::InternalServerError),
                    }
                }
                None => Response::new(Version::Http11, StatusCode::BadRequest),
            },
            _ => Response::new(Version::Http11, StatusCode::BadRequest),
        }
    }
}

// /api/v1/mount handler
pub struct MountHandler {}

impl EndpointHandler for MountHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Put => {
                match &req.body {
                    Some(body) => {
                        // Deserialize into a MountInfo
                        let info: MountInfo = match serde_json::from_slice(body.raw())
                            .map_err(HttpError::SerdeJsonDeserialize)
                        {
                            Ok(config) => config,
                            Err(e) => return error_response(e, StatusCode::BadRequest),
                        };

                        // Call mount_info()
                        match mount_info(api_notifier, api_sender, info).map_err(HttpError::Mount) {
                            Ok(_) => Response::new(Version::Http11, StatusCode::NoContent),
                            Err(e) => error_response(e, StatusCode::InternalServerError),
                        }
                    }

                    None => Response::new(Version::Http11, StatusCode::BadRequest),
                }
            }

            _ => Response::new(Version::Http11, StatusCode::BadRequest),
        }
    }
}

pub struct MetricsHandler {}

impl EndpointHandler for MetricsHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Get => {
                match export_global_stats(api_notifier, api_sender).map_err(HttpError::Info) {
                    Ok(info) => {
                        let mut response = Response::new(Version::Http11, StatusCode::OK);
                        response.set_body(Body::new(info));
                        response
                    }
                    Err(e) => error_response(e, StatusCode::InternalServerError),
                }
            }
            _ => Response::new(Version::Http11, StatusCode::BadRequest),
        }
    }
}

pub struct MetricsFilesHandler {}

impl EndpointHandler for MetricsFilesHandler {
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response {
        match req.method() {
            Method::Get => {
                match export_files_stats(api_notifier, api_sender).map_err(HttpError::Info) {
                    Ok(info) => {
                        let mut response = Response::new(Version::Http11, StatusCode::OK);
                        response.set_body(Body::new(info));
                        response
                    }
                    Err(e) => error_response(e, StatusCode::InternalServerError),
                }
            }
            _ => Response::new(Version::Http11, StatusCode::BadRequest),
        }
    }
}
