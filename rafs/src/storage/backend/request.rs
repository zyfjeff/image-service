// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use reqwest::blocking::{Body, Client, Response};
use reqwest::{self, header::HeaderMap, Method, StatusCode};
use std::fs::File;
use std::io::Read;
use std::io::Result as IOResult;
use std::io::{Error, ErrorKind};
use url::Url;

pub struct Progress {
  inner: File,
  current: u64,
  total: u64,
  callback: fn((u64, u64)),
}

impl Progress {
  fn new(file: File, total: u64, callback: fn((u64, u64))) -> Progress {
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

pub struct Request {
  scheme: String,
  endpoint: String,
  client: Client,
}

pub fn new(scheme: &str, endpoint: &str) -> Request {
  Request {
    scheme: String::from(scheme),
    endpoint: String::from(endpoint),
    client: Client::new(),
  }
}

impl Request {
  pub fn request(
    &self,
    method: &str,
    data: FileBody,
    headers: HeaderMap,
    query: &[&str],
  ) -> Result<Response, Error> {
    let url = format!("{}://{}", self.scheme, self.endpoint);
    let url = Url::parse(url.as_str()).unwrap();

    let mut query_str = String::new();
    if query.len() > 0 {
      query_str = format!("?{}", query.join("&"));
    }

    let url = format!("{}{}", url.as_str(), query_str);
    debug!("request {:?} method {:?} url {:?}", headers, method, url);

    let method = Method::from_bytes(method.as_bytes()).unwrap();
    let rb = self.client.request(method, url.as_str()).headers(headers);

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
