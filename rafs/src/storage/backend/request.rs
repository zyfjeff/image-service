// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::io::Result;

use reqwest::blocking::{Body, Client, Response};
use reqwest::{self, Method, StatusCode};

use super::ReqErr;

pub use reqwest::header::HeaderMap;

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
    StaticBuf(&'static [u8]),
}

impl<R> ReqBody<R> {
    /// Create an ReqBody from a static buffer.
    ///
    /// ReqBody::Vec needs to create a new Vector and copy data into the new Vector.
    /// So reuse the data buffer from the caller to avoid  avoid unnecessary memory copy.
    ///
    /// # Safety
    /// The caller needs to ensure the data buffer is valid or out-lives the ReqBody object.
    // of the referenced slice.
    pub unsafe fn from_static_slice(buf: &[u8]) -> Self {
        ReqBody::StaticBuf(std::mem::transmute::<&[u8], &'static [u8]>(buf))
    }
}

#[derive(Debug, Default)]
pub struct Request {
    client: Client,
}

impl Request {
    pub fn new(proxy: Option<&String>) -> Result<Request> {
        let mut cb = Client::builder().timeout(None);
        if let Some(proxy) = proxy {
            cb = cb.proxy(reqwest::Proxy::all(proxy).map_err(ReqErr::inv_input)?)
        }

        Ok(Request {
            client: cb.build().map_err(ReqErr::inv_input)?,
        })
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
            ReqBody::StaticBuf(buf) => {
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
