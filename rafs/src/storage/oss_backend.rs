// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base64;
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use httpdate;
use reqwest::{self, header::HeaderMap, StatusCode};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::io::Result as IOResult;
use std::io::{Error, ErrorKind};
use std::time::SystemTime;
use url::Url;

use crate::storage::backend::BlobBackend;

const HEADER_DATE: &str = "Date";
const HEADER_AUTHORIZATION: &str = "Authorization";

struct Progress {
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

enum Body {
    File(Progress, u64),
    Buf(Vec<u8>),
}

#[derive(Debug)]
pub struct OSS {
    client: reqwest::Client,
    access_key_id: String,
    access_key_secret: String,
    endpoint: String,
    bucket_name: String,
}

impl OSS {
    pub fn new(
        endpoint: &str,
        access_key_id: &str,
        access_key_secret: &str,
        bucket_name: &str,
    ) -> OSS {
        OSS {
            client: reqwest::Client::new(),
            endpoint: String::from(endpoint),
            access_key_id: String::from(access_key_id),
            access_key_secret: String::from(access_key_secret),
            bucket_name: String::from(bucket_name),
        }
    }

    pub fn put_object(&self, blob_id: &str, file: File, callback: fn((u64, u64))) -> IOResult<()> {
        let headers = HeaderMap::new();
        let size = file.metadata().unwrap().len();
        let body = Progress::new(file, size, callback);
        self.request(
            "PUT",
            Body::File(body, size),
            self.bucket_name.as_str(),
            blob_id,
            headers,
            &[],
        )?;
        Ok(())
    }

    /// generate oss request signature
    fn sign(&self, verb: &str, headers: &HeaderMap, canonicalized_resource: &str) -> String {
        let content_md5 = "";
        let content_type = "";
        let mut canonicalized_oss_headers = vec![];
        let date = headers.get(HEADER_DATE).unwrap().to_str().unwrap();

        let mut data = vec![
            verb,
            content_md5,
            content_type,
            date,
            // canonicalized_oss_headers,
            canonicalized_resource,
        ];
        for (name, value) in headers.into_iter() {
            let name = name.as_str();
            if name.starts_with("x-oss-") {
                let header = format!("{}:{}", name.to_lowercase(), value.to_str().unwrap());
                canonicalized_oss_headers.push(header);
            }
        }
        let canonicalized_oss_headers = canonicalized_oss_headers.join("\n");
        if canonicalized_oss_headers != "" {
            data.insert(4, canonicalized_oss_headers.as_str());
        }
        let data = data.join("\n");
        let mut mac = Hmac::new(Sha1::new(), self.access_key_secret.as_bytes());
        mac.input(data.as_bytes());
        let signature = format!("{}", base64::encode(mac.result().code()));

        format!("OSS {}:{}", self.access_key_id, signature)
    }

    /// generic oss api request
    fn request(
        &self,
        method: &str,
        data: Body,
        bucket_name: &str,
        object_key: &str,
        headers: HeaderMap,
        query: &[&str],
    ) -> Result<reqwest::Response, Error> {
        let date = httpdate::fmt_http_date(SystemTime::now());
        let mut new_headers = HeaderMap::new();
        new_headers.extend(headers);
        new_headers.insert(HEADER_DATE, date.as_str().parse().unwrap());
        let mut host_prefix = String::new();
        if bucket_name != "" {
            host_prefix = format!("{}.", bucket_name);
        }
        let url = format!("https://{}{}", host_prefix, self.endpoint);
        let mut url = Url::parse(url.as_str()).unwrap();
        url.path_segments_mut().unwrap().push(object_key);
        let mut query_str = String::new();
        if query.len() > 0 {
            query_str = format!("?{}", query.join("&"));
        }
        let mut prefix = String::new();
        if bucket_name != "" {
            prefix = format!("/{}", bucket_name);
        }
        let resource = format!("{}/{}{}", prefix, object_key, query_str);
        let url = format!("{}{}", url.as_str(), query_str);
        debug!(
            "oss request {:?} method {:?} url {:?}",
            new_headers, method, url
        );

        let authorization = self.sign(method, &new_headers, resource.as_str());
        new_headers.insert(
            HEADER_AUTHORIZATION,
            authorization.as_str().parse().unwrap(),
        );
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();

        let rb = self
            .client
            .request(method, url.as_str())
            .headers(new_headers);

        let ret;
        match data {
            Body::File(body, total) => {
                let body = reqwest::Body::sized(body, total);
                ret = rb.body(body).send();
            }
            Body::Buf(buf) => {
                ret = rb.body(buf).send();
            }
        }

        match ret {
            Ok(mut resp) => {
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

    fn create_bucket(&self) -> IOResult<()> {
        let headers = HeaderMap::new();
        self.request(
            "PUT",
            Body::Buf("".as_bytes().to_vec()),
            self.bucket_name.as_str(),
            "",
            headers,
            &[],
        )?;
        Ok(())
    }
}

pub fn new() -> OSS {
    OSS {
        client: reqwest::Client::new(),
        access_key_id: String::new(),
        access_key_secret: String::new(),
        endpoint: String::new(),
        bucket_name: String::new(),
    }
}

fn einval() -> Error {
    Error::from_raw_os_error(libc::EINVAL)
}

impl BlobBackend for OSS {
    fn init(&mut self, config: HashMap<&str, &str>) -> IOResult<()> {
        let endpoint = config.get("endpoint").ok_or(einval())?;
        let access_key_id = config.get("access_key_id").ok_or(einval())?;
        let access_key_secret = config.get("access_key_secret").ok_or(einval())?;
        let bucket_name = config.get("bucket_name").ok_or(einval())?;
        self.endpoint = (*endpoint).to_owned();
        self.access_key_id = (*access_key_id).to_owned();
        self.access_key_secret = (*access_key_secret).to_owned();
        self.bucket_name = (*bucket_name).to_owned();
        // self.create_bucket()?;
        Ok(())
    }

    /// read ranged data from oss object
    fn read(&self, blob_id: &str, buf: &mut Vec<u8>, offset: u64, count: usize) -> IOResult<usize> {
        let mut headers = HeaderMap::new();
        let end_at = offset + count as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.as_str().parse().unwrap());
        let mut resp = self.request(
            "GET",
            Body::Buf("".as_bytes().to_vec()),
            self.bucket_name.as_str(),
            blob_id,
            headers,
            &[],
        )?;
        let ret = resp.copy_to(buf);
        match ret {
            Ok(size) => Ok(size as usize),
            Err(err) => Err(Error::new(ErrorKind::BrokenPipe, format!("{}", err))),
        }
    }

    /// append data to oss object
    fn write(&self, blob_id: &str, buf: &Vec<u8>, offset: u64) -> IOResult<usize> {
        let headers = HeaderMap::new();
        let position = format!("position={}", offset);
        self.request(
            "POST",
            Body::Buf(buf.to_vec()),
            self.bucket_name.as_str(),
            blob_id,
            headers,
            &["append", position.as_str()],
        )?;
        Ok(buf.len())
    }

    fn close(&mut self) {}
}
