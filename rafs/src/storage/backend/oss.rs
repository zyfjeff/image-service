// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use std::collections::HashMap;
use std::fs::File;
use std::io::Result;
use std::time::SystemTime;
use url::Url;

use crate::storage::backend::request::{HeaderMap, Progress, ReqBody, Request};
use crate::storage::backend::ReqErr;
use crate::storage::backend::{BlobBackend, BlobBackendUploader};

const HEADER_DATE: &str = "Date";
const HEADER_AUTHORIZATION: &str = "Authorization";

#[derive(Debug)]
pub struct OSS {
    request: Request,
    access_key_id: String,
    access_key_secret: String,
    scheme: String,
    endpoint: String,
    bucket_name: String,
}

impl OSS {
    /// generate oss request signature
    fn sign(
        &self,
        verb: &str,
        headers: HeaderMap,
        canonicalized_resource: &str,
    ) -> Result<HeaderMap> {
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
            let value = value.to_str().map_err(ReqErr::inv_input)?;
            if name.starts_with("x-oss-") {
                let header = format!("{}:{}", name.to_lowercase(), value);
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
        let signature = base64::encode(mac.result().code());

        let authorization = format!("OSS {}:{}", self.access_key_id, signature);

        let mut new_headers = HeaderMap::new();
        new_headers.extend(headers);
        new_headers.insert(
            HEADER_DATE,
            date.as_str().parse().map_err(ReqErr::inv_data)?,
        );
        new_headers.insert(
            HEADER_AUTHORIZATION,
            authorization.as_str().parse().map_err(ReqErr::inv_data)?,
        );

        Ok(new_headers)
    }

    fn resource(&self, object_key: &str, query_str: &str) -> String {
        let prefix = if self.bucket_name != "" {
            format!("/{}", self.bucket_name)
        } else {
            String::new()
        };
        format!("{}/{}{}", prefix, object_key, query_str)
    }

    fn url(&self, object_key: &str, query: &[&str]) -> Result<(String, String)> {
        let host_prefix = if self.bucket_name != "" {
            format!("{}.", self.bucket_name)
        } else {
            String::new()
        };

        let url = format!("{}://{}{}", self.scheme, host_prefix, self.endpoint);
        let mut url = Url::parse(url.as_str()).map_err(ReqErr::inv_data)?;
        url.path_segments_mut()
            .map_err(ReqErr::inv_data)?
            .push(object_key);

        let query_str = if !query.is_empty() {
            format!("?{}", query.join("&"))
        } else {
            String::new()
        };

        let resource = self.resource(object_key, query_str.as_str());
        let url = format!("{}{}", url.as_str(), query_str);

        Ok((resource, url))
    }

    fn create_bucket(&self) -> Result<()> {
        let method = "PUT";
        let query = &[];
        let (resource, url) = self.url("", query)?;
        let headers = self.sign(method, HeaderMap::new(), resource.as_str())?;

        self.request
            .call::<&[u8]>(method, url.as_str(), ReqBody::Buf(b"".to_vec()), headers)?;

        Ok(())
    }
}

pub fn new<S: std::hash::BuildHasher>(config: &HashMap<String, String, S>) -> Result<OSS> {
    let endpoint = config
        .get("endpoint")
        .ok_or_else(|| ReqErr::inv_input("endpoint required"))?;
    let access_key_id = config
        .get("access_key_id")
        .ok_or_else(|| ReqErr::inv_input("access_key_id required"))?;
    let access_key_secret = config
        .get("access_key_secret")
        .ok_or_else(|| ReqErr::inv_input("access_key_secret required"))?;
    let bucket_name = config
        .get("bucket_name")
        .ok_or_else(|| ReqErr::inv_input("bucket_name required"))?;

    let endpoint = (*endpoint).to_owned();
    let access_key_id = (*access_key_id).to_owned();
    let access_key_secret = (*access_key_secret).to_owned();
    let bucket_name = (*bucket_name).to_owned();

    let scheme = if let Some(scheme) = config.get("scheme") {
        (*scheme).to_owned()
    } else {
        String::from("https")
    };
    let request = Request::new(config.get("proxy"))?;

    Ok(OSS {
        scheme,
        endpoint,
        access_key_id,
        access_key_secret,
        bucket_name,
        request,
    })
}

impl BlobBackend for OSS {
    /// read ranged data from oss object
    fn read(&self, blob_id: &str, mut buf: &mut [u8], offset: u64) -> Result<usize> {
        let method = "GET";
        let query = &[];
        let (resource, url) = self.url(blob_id, query)?;

        let mut headers = HeaderMap::new();
        let end_at = offset + buf.len() as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.as_str().parse().map_err(ReqErr::inv_data)?);
        let headers = self.sign(method, headers, resource.as_str())?;

        let mut resp = self
            .request
            .call::<&[u8]>(method, url.as_str(), ReqBody::Buf(b"".to_vec()), headers)
            .or_else(|e| {
                error!("oss req failed {:?}", e);
                Err(e)
            })?;

        resp.copy_to(&mut buf)
            .or_else(|err| {
                error!("oss read failed {:?}", err);
                Err(ReqErr::broken_pipe(err))
            })
            .map(|size| size as usize)
    }

    /// append data to oss object
    fn write(&self, blob_id: &str, buf: &[u8], offset: u64) -> Result<usize> {
        let method = "POST";
        let position = format!("position={}", offset);
        let query = &["append", position.as_str()];
        let (resource, url) = self.url(blob_id, query)?;
        let headers = self.sign(method, HeaderMap::new(), resource.as_str())?;

        self.request
            .call::<&[u8]>(method, url.as_str(), ReqBody::Buf(buf.to_vec()), headers)?;

        Ok(buf.len())
    }

    fn close(&mut self) {}
}

impl BlobBackendUploader for OSS {
    type Reader = File;

    fn upload(
        &self,
        blob_id: &str,
        file: File,
        size: usize,
        callback: fn((usize, usize)),
    ) -> Result<usize> {
        let method = "PUT";
        let query = &[];
        let (resource, url) = self.url(blob_id, query)?;
        let headers = self.sign(method, HeaderMap::new(), resource.as_str())?;

        let body = Progress::new(file, size, callback);

        self.request
            .call(method, url.as_str(), ReqBody::Read(body, size), headers)?;

        Ok(size as usize)
    }
}
