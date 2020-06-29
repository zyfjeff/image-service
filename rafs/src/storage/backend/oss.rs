// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::Result;
use std::time::SystemTime;

use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use url::Url;

use crate::storage::backend::request::{HeaderMap, Progress, ReqBody, Request};
use crate::storage::backend::{BlobBackend, BlobBackendUploader};

use nydus_error::{einval, epipe};

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
        mut headers: HeaderMap,
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
            let value = value.to_str().map_err(|e| einval!(e))?;
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

        headers.insert(HEADER_DATE, date.as_str().parse().map_err(|e| einval!(e))?);
        headers.insert(
            HEADER_AUTHORIZATION,
            authorization.as_str().parse().map_err(|e| einval!(e))?,
        );

        Ok(headers)
    }

    fn resource(&self, object_key: &str, query_str: &str) -> String {
        if self.bucket_name != "" {
            format!("/{}/{}{}", self.bucket_name, object_key, query_str)
        } else {
            format!("/{}{}", object_key, query_str)
        }
    }

    fn url(&self, object_key: &str, query: &[&str]) -> Result<(String, String)> {
        let url = if self.bucket_name != "" {
            format!("{}://{}.{}", self.scheme, self.bucket_name, self.endpoint)
        } else {
            format!("{}://{}", self.scheme, self.endpoint)
        };
        let mut url = Url::parse(url.as_str()).map_err(|e| einval!(e))?;

        url.path_segments_mut()
            .map_err(|e| einval!(e))?
            .push(object_key);

        if query.is_empty() {
            Ok((self.resource(object_key, ""), url.to_string()))
        } else {
            let query_str = format!("?{}", query.join("&"));
            let resource = self.resource(object_key, &query_str);
            let url = format!("{}{}", url.as_str(), &query_str);

            Ok((resource, url))
        }
    }

    /*
    fn create_bucket(&self) -> Result<()> {
        let method = "PUT";
        let query = &[];
        let (resource, url) = self.url("", query)?;
        let headers = self.sign(method, HeaderMap::new(), resource.as_str())?;

        // Safe because the the call() is a synchronous operation.
        let data = unsafe { ReqBody::from_static_slice(b"") };
        self.request
            .call::<&[u8]>(method, url.as_str(), data, headers)?;

        Ok(())
    }
     */
}

pub fn new<S: ::std::hash::BuildHasher>(config: &HashMap<String, String, S>) -> Result<OSS> {
    let endpoint = config
        .get("endpoint")
        .map(|s| s.to_owned())
        .ok_or_else(|| einval!("endpoint required"))?;
    let access_key_id = config
        .get("access_key_id")
        .map(|s| s.to_owned())
        .ok_or_else(|| einval!("access_key_id required"))?;
    let access_key_secret = config
        .get("access_key_secret")
        .map(|s| s.to_owned())
        .ok_or_else(|| einval!("access_key_secret required"))?;
    let bucket_name = config
        .get("bucket_name")
        .map(|s| s.to_owned())
        .ok_or_else(|| einval!("bucket_name required"))?;

    let scheme = if let Some(scheme) = config.get("scheme") {
        scheme.to_owned()
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
        headers.insert("Range", range.as_str().parse().map_err(|e| einval!(e))?);
        let headers = self.sign(method, headers, resource.as_str())?;

        // Safe because the the call() is a synchronous operation.
        let data = unsafe { ReqBody::from_static_slice(b"") };
        let mut resp = self
            .request
            .call::<&[u8]>(method, url.as_str(), data, headers)
            .or_else(|e| Err(einval!(format!("oss req failed {:?}", e))))?;

        resp.copy_to(&mut buf)
            .or_else(|err| Err(epipe!(format!("oss read failed {:?}", err))))
            .map(|size| size as usize)
    }

    /// append data to oss object
    fn write(&self, blob_id: &str, buf: &[u8], offset: u64) -> Result<usize> {
        let method = "POST";
        let position = format!("position={}", offset);
        let query = &["append", position.as_str()];
        let (resource, url) = self.url(blob_id, query)?;
        let headers = self.sign(method, HeaderMap::new(), resource.as_str())?;

        // Safe because the the call() is a synchronous operation.
        let data = unsafe { ReqBody::from_static_slice(buf) };
        self.request
            .call::<&[u8]>(method, url.as_str(), data, headers)?;

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
