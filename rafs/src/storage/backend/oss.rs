// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base64;
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use httpdate;
use reqwest::{self, header::HeaderMap};
use std::collections::HashMap;
use std::fs::File;
use std::io::Result as IOResult;
use std::io::{Error, ErrorKind};
use std::time::SystemTime;
use url::Url;

use crate::storage::backend::request::{FileBody, Progress, Request};
use crate::storage::backend::BlobBackend;

const HEADER_DATE: &str = "Date";
const HEADER_AUTHORIZATION: &str = "Authorization";

#[derive(Debug)]
pub struct OSS {
    request: Request,
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
            request: Request::new(),
            endpoint: String::from(endpoint),
            access_key_id: String::from(access_key_id),
            access_key_secret: String::from(access_key_secret),
            bucket_name: String::from(bucket_name),
        }
    }

    pub fn put_object(&self, blob_id: &str, file: File, callback: fn((u64, u64))) -> IOResult<()> {
        let method = "PUT";
        let query = &[];
        let (resource, url) = self.url(blob_id, query);
        let headers = self.sign(method, HeaderMap::new(), resource.as_str());

        let size = file.metadata().unwrap().len();
        let body = Progress::new(file, size, callback);

        self.request
            .call(method, url.as_str(), FileBody::File(body, size), headers)?;

        Ok(())
    }

    /// generate oss request signature
    fn sign(&self, verb: &str, headers: HeaderMap, canonicalized_resource: &str) -> HeaderMap {
        let content_md5 = "";
        let content_type = "";
        let mut canonicalized_oss_headers = vec![];

        let date = httpdate::fmt_http_date(SystemTime::now());

        let mut data = vec![
            verb,
            content_md5,
            content_type,
            date.as_str(),
            // canonicalized_oss_headers,
            canonicalized_resource,
        ];
        for (name, value) in &headers {
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

        let authorization = format!("OSS {}:{}", self.access_key_id, signature);

        let mut new_headers = HeaderMap::new();
        new_headers.extend(headers);
        new_headers.insert(HEADER_DATE, date.as_str().parse().unwrap());
        new_headers.insert(
            HEADER_AUTHORIZATION,
            authorization.as_str().parse().unwrap(),
        );

        new_headers
    }

    fn resource(&self, object_key: &str, query_str: &str) -> String {
        let mut prefix = String::new();
        if self.bucket_name != "" {
            prefix = format!("/{}", self.bucket_name);
        }
        format!("{}/{}{}", prefix, object_key, query_str)
    }

    fn url(&self, object_key: &str, query: &[&str]) -> (String, String) {
        let mut host_prefix = String::new();
        if self.bucket_name != "" {
            host_prefix = format!("{}.", self.bucket_name);
        }

        let url = format!("https://{}{}", host_prefix, self.endpoint);
        let mut url = Url::parse(url.as_str()).unwrap();
        url.path_segments_mut().unwrap().push(object_key);

        let mut query_str = String::new();
        if query.len() > 0 {
            query_str = format!("?{}", query.join("&"));
        }

        let resource = self.resource(object_key, query_str.as_str());
        let url = format!("{}{}", url.as_str(), query_str);

        (resource, url)
    }

    fn create_bucket(&self) -> IOResult<()> {
        let method = "PUT";
        let query = &[];
        let (resource, url) = self.url("", query);
        let headers = self.sign(method, HeaderMap::new(), resource.as_str());

        self.request.call(
            method,
            url.as_str(),
            FileBody::Buf("".as_bytes().to_vec()),
            headers,
        )?;

        Ok(())
    }
}

pub fn new() -> OSS {
    OSS {
        request: Request::new(),
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
        self.request = Request::new();
        // self.create_bucket()?;
        Ok(())
    }

    /// read ranged data from oss object
    fn read(&self, blob_id: &str, buf: &mut Vec<u8>, offset: u64, count: usize) -> IOResult<usize> {
        let method = "GET";
        let query = &[];
        let (resource, url) = self.url(blob_id, query);

        let mut headers = HeaderMap::new();
        let end_at = offset + count as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.as_str().parse().unwrap());
        let headers = self.sign(method, headers, resource.as_str());

        let mut resp = self
            .request
            .call(
                method,
                url.as_str(),
                FileBody::Buf("".as_bytes().to_vec()),
                headers,
            )
            .or_else(|e| {
                error!("oss req failed {:?}", e);
                Err(e)
            })?;

        resp.copy_to(buf)
            .or_else(|err| {
                error!("oss read failed {:?}", err);
                Err(Error::new(ErrorKind::BrokenPipe, format!("{}", err)))
            })
            .map(|size| size as usize)
    }

    /// append data to oss object
    fn write(&self, blob_id: &str, buf: &Vec<u8>, offset: u64) -> IOResult<usize> {
        let method = "POST";
        let position = format!("position={}", offset);
        let query = &["append", position.as_str()];
        let (resource, url) = self.url(blob_id, query);
        let headers = self.sign(method, HeaderMap::new(), resource.as_str());

        self.request
            .call(method, url.as_str(), FileBody::Buf(buf.to_vec()), headers)?;
        Ok(buf.len())
    }

    fn close(&mut self) {}
}
