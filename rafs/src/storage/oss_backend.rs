// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base64;
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use httpdate;
use reqwest::{self, header::HeaderMap, StatusCode};
use std::collections::HashMap;
use std::io::Result as IOResult;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use url::Url;

use crate::storage::backend::BlobBackend;

const HEADER_DATE: &str = "Date";
const HEADER_AUTHORIZATION: &str = "Authorization";

#[derive(Default, Clone)]
struct OSSTarget {
    path: String,
}

impl OSSTarget {
    fn new(blob_id: &str) -> OSSTarget {
        OSSTarget {
            path: blob_id.to_owned(),
        }
    }
}

pub struct OSS {
    access_key_id: String,
    access_key_secret: String,
    endpoint: String,
    bucket_name: String,
    targets: RwLock<HashMap<String, Arc<Mutex<OSSTarget>>>>,
}

impl OSS {
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
    fn request<T: Into<reqwest::Body>>(
        &self,
        method: &str,
        data: T,
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
        url = url.join(object_key).unwrap();
        let mut query_str = String::new();
        if query.len() > 0 {
            query_str = format!("?{}", query.join("&"));
        }
        let mut prefix = String::new();
        if bucket_name != "" {
            prefix = format!("/{}", bucket_name);
        }
        let resource = format!("{}/{}{}", prefix, object_key, query_str);
        let authorization = self.sign(method, &new_headers, resource.as_str());
        new_headers.insert(
            HEADER_AUTHORIZATION,
            authorization.as_str().parse().unwrap(),
        );
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let client = reqwest::Client::new();
        let url = format!("{}{}", url.as_str(), query_str);
        println!("{} {}", method, url);
        let ret = client
            .request(method, url.as_str())
            .headers(new_headers)
            .body(data)
            .send();
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
    fn create_bucket(&self, bucket_name: &str) -> IOResult<()> {
        let headers = HeaderMap::new();
        self.request("PUT", "", bucket_name, "", headers, &[])?;
        Ok(())
    }
}

pub fn new(config: HashMap<&str, &str>) -> OSS {
    let endpoint = config.get("endpoint").unwrap();
    let access_key_id = config.get("access_key_id").unwrap();
    let access_key_secret = config.get("access_key_secret").unwrap();
    let bucket_name = config.get("bucket_name").unwrap();
    OSS {
        targets: RwLock::new(HashMap::new()),
        endpoint: (*endpoint).to_owned(),
        access_key_id: (*access_key_id).to_owned(),
        access_key_secret: (*access_key_secret).to_owned(),
        bucket_name: (*bucket_name).to_owned(),
    }
}

impl BlobBackend for OSS {
    fn init(&mut self, _config: HashMap<&str, &str>) -> IOResult<()> {
        self.create_bucket(self.bucket_name.as_str())
    }

    // Read a range of data from blob into the provided destination
    fn read(&self, blob_id: &str, buf: &mut Vec<u8>, offset: u64) -> IOResult<usize> {
        let mut headers = HeaderMap::new();
        let end_at = buf.len() - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.as_str().parse().unwrap());
        let mut resp = self.request("GET", "", self.bucket_name.as_str(), blob_id, headers, &[])?;
        let ret = resp.copy_to(buf);
        match ret {
            Ok(size) => Ok(size as usize),
            Err(err) => Err(Error::new(ErrorKind::Other, format!("{}", err))),
        }
    }

    // Write a range of data to blob from the provided source
    fn write(&self, blob_id: &str, buf: &Vec<u8>, offset: u64) -> IOResult<usize> {
        let headers = HeaderMap::new();
        let position = format!("position={}", offset);
        self.request(
            "POST",
            buf.to_owned(),
            self.bucket_name.as_str(),
            blob_id,
            headers,
            &["append", position.as_str()],
        )?;
        Ok(buf.len())
    }

    fn close(&mut self) {}
}
