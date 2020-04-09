// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use reqwest::blocking::{Body, Client, Response};
use reqwest::{self, header::HeaderMap, Method, StatusCode};
use std::fs::File;
use std::io::Read;
use std::io::Result as IOResult;
use std::io::{Error, ErrorKind};

pub struct Progress {
  inner: File,
  current: u64,
  total: u64,
  callback: fn((u64, u64)),
}

impl Progress {
  pub fn new(file: File, total: u64, callback: fn((u64, u64))) -> Progress {
    Progress {
      inner: file,
      current: 0,
      total,
      callback,
    }
  }
}

impl Read for Progress {
  fn read(&mut self, buf: &mut [u8]) -> IOResult<usize> {
    self.inner.read(buf).map(|count| {
      self.current += count as u64;
      (self.callback)((self.current, self.total));
      count
    })
  }
}

pub enum FileBody {
  File(Progress, u64),
  Buf(Vec<u8>),
}

#[derive(Debug)]
pub struct Request {
  client: Client,
}

impl Request {
  pub fn new() -> Request {
    let client = Client::builder().timeout(None).build().unwrap();
    Request { client }
  }

  pub fn call(
    &self,
    method: &str,
    url: &str,
    data: FileBody,
    headers: HeaderMap,
  ) -> Result<Response, Error> {
    debug!("request {:?} method {:?} url {:?}", headers, method, url);

    let method = Method::from_bytes(method.as_bytes()).unwrap();

    let rb = self.client.request(method, url).headers(headers);

    let ret;
    match data {
      FileBody::File(body, total) => {
        let body = Body::sized(body, total);
        ret = rb.body(body).send();
      }
      FileBody::Buf(buf) => {
        ret = rb.body(buf).send();
      }
    }

    match ret {
      Ok(resp) => {
        let status = resp.status();
        if status >= StatusCode::OK && status < StatusCode::MULTIPLE_CHOICES {
          return Ok(resp);
        }
        let message = resp.text().unwrap();
        Err(Error::new(ErrorKind::Other, message))
      }
      Err(err) => Err(Error::new(ErrorKind::Other, format!("{}", err))),
    }
  }
}
