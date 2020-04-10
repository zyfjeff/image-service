// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use reqwest::blocking::{Body, Client, Response};
pub use reqwest::header::HeaderMap;
use reqwest::{self, Method, StatusCode};
use std::io::Read;
use std::io::Result;
use std::io::{Error, ErrorKind};

pub struct ReqErr {}

impl ReqErr {
    pub fn inv_input<E: std::fmt::Debug>(err: E) -> Error {
        Error::new(ErrorKind::InvalidInput, format!("{:?}", err))
    }
    pub fn inv_data<E: std::fmt::Debug>(err: E) -> Error {
        Error::new(ErrorKind::InvalidData, format!("{:?}", err))
    }
    pub fn other<E: std::fmt::Debug>(err: E) -> Error {
        Error::new(ErrorKind::Other, format!("{:?}", err))
    }
    pub fn broken_pipe<E: std::fmt::Debug>(err: E) -> Error {
        Error::new(ErrorKind::BrokenPipe, format!("{:?}", err))
    }
}

pub struct Progress<R> {
    inner: R,
    current: usize,
    total: usize,
    callback: fn((usize, usize)),
}

impl<R> Progress<R> {
    pub fn new(r: R, total: usize, callback: fn((usize, usize))) -> Progress<R> {
        Progress {
            inner: r,
            current: 0,
            total,
            callback,
        }
    }
}

impl<R: Read + Send + 'static> Read for Progress<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner.read(buf).map(|count| {
            self.current += count as usize;
            (self.callback)((self.current, self.total));
            count
        })
    }
}

pub enum ReqBody<R> {
    Read(Progress<R>, usize),
    Buf(Vec<u8>),
}

#[derive(Debug)]
pub struct Request {
    client: Client,
}

impl Request {
    pub fn new() -> Request {
        Request {
            client: Client::builder().timeout(None).build().unwrap(),
        }
    }

    pub fn call<R: Read + Send + 'static>(
        &self,
        method: &str,
        url: &str,
        data: ReqBody<R>,
        headers: HeaderMap,
    ) -> Result<Response> {
        let method = Method::from_bytes(method.as_bytes()).map_err(ReqErr::inv_input)?;

        let rb = self.client.request(method, url).headers(headers);

        let ret;
        match data {
            ReqBody::Read(body, total) => {
                let body = Body::sized(body, total as u64);
                ret = rb.body(body).send();
            }
            ReqBody::Buf(buf) => {
                ret = rb.body(buf).send();
            }
        }

        match ret {
            Ok(resp) => {
                let status = resp.status();
                if status >= StatusCode::OK && status < StatusCode::MULTIPLE_CHOICES {
                    return Ok(resp);
                }

                let message = resp.text().map_err(ReqErr::broken_pipe)?;

                Err(ReqErr::inv_input(message))
            }
            Err(err) => Err(ReqErr::broken_pipe(err)),
        }
    }
}
