// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::io::Result;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::thread;

use micro_http::{HttpServer, MediaType, Request, Response, StatusCode, Version};
use vmm_sys_util::eventfd::EventFd;

use crate::http_endpoint::{
    ApiRequest, InfoHandler, MetricsFilesHandler, MetricsHandler, MountHandler,
};

const HTTP_ROOT: &str = "/api/v1";

/// An HTTP endpoint handler interface
pub trait EndpointHandler: Sync + Send {
    /// Handles an HTTP request.
    /// After parsing the request, the handler could decide to send an
    /// associated API request down to the VMM API server to e.g. create
    /// or start a VM. The request will block waiting for an answer from the
    /// API server and translate that into an HTTP response.
    fn handle_request(
        &self,
        req: &Request,
        api_notifier: EventFd,
        api_sender: Sender<ApiRequest>,
    ) -> Response;
}

/// An HTTP routes structure.
pub struct HttpRoutes {
    /// routes is a hash table mapping endpoint URIs to their endpoint handlers.
    pub routes: HashMap<String, Box<dyn EndpointHandler + Sync + Send>>,
}

macro_rules! endpoint {
    ($path:expr) => {
        format!("{}{}", HTTP_ROOT, $path)
    };
}

lazy_static! {
    /// HTTP_ROUTES contain all the cloud-hypervisor HTTP routes.
    pub static ref HTTP_ROUTES: HttpRoutes = {
        let mut r = HttpRoutes {
            routes: HashMap::new(),
        };

        r.routes.insert(endpoint!("/daemon"), Box::new(InfoHandler{}));
        r.routes.insert(endpoint!("/mount"), Box::new(MountHandler{}));
        r.routes.insert(endpoint!("/metrics"), Box::new(MetricsHandler{}));
        r.routes.insert(endpoint!("/metrics/files"), Box::new(MetricsFilesHandler{}));
        r
    };
}

fn handle_http_request(
    request: &Request,
    api_notifier: &EventFd,
    api_sender: &Sender<ApiRequest>,
) -> Response {
    let path = request.uri().get_abs_path().to_string();
    let mut response = match HTTP_ROUTES.routes.get(&path) {
        Some(route) => match api_notifier.try_clone() {
            Ok(notifier) => route.handle_request(&request, notifier, api_sender.clone()),
            Err(_) => Response::new(Version::Http11, StatusCode::InternalServerError),
        },
        None => Response::new(Version::Http11, StatusCode::NotFound),
    };

    response.set_server("Nydus API");
    response.set_content_type(MediaType::ApplicationJson);
    response
}

pub fn start_http_thread(
    path: &str,
    api_notifier: EventFd,
    api_sender: Sender<ApiRequest>,
) -> Result<thread::JoinHandle<Result<()>>> {
    std::fs::remove_file(path).unwrap_or_default();
    let socket_path = PathBuf::from(path);

    thread::Builder::new()
        .name("http-server".to_string())
        .spawn(move || {
            let mut server = HttpServer::new(socket_path).unwrap();
            server.start_server().unwrap();
            info!("http server started");
            loop {
                match server.requests() {
                    Ok(request_vec) => {
                        for server_request in request_vec {
                            server
                                .respond(server_request.process(|request| {
                                    handle_http_request(request, &api_notifier, &api_sender)
                                }))
                                .or_else(|e| -> Result<()> {
                                    error!("HTTP server error on response: {}", e);
                                    Ok(())
                                })?;
                        }
                    }
                    Err(e) => {
                        error!(
                            "HTTP server error on retrieving incoming request. Error: {}",
                            e
                        );
                    }
                }
            }
        })
}
