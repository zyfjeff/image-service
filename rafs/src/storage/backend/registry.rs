// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::fs::File;
use std::io::Result;
use url::Url;

use crate::storage::backend::request::{HeaderMap, Progress, ReqBody, ReqErr, Request};
use crate::storage::backend::{BlobBackend, BlobBackendUploader};

const HEADER_CONTENT_LENGTH: &str = "Content-Length";
const HEADER_CONTENT_TYPE: &str = "Content-Type";
const HEADER_LOCATION: &str = "LOCATION";
const HEADER_OCTET_STREAM: &str = "application/octet-stream";

#[derive(Debug)]
pub struct Registry {
    request: Request,
    scheme: String,
    host: String,
    repo: String,
}

impl Registry {
    pub fn default() -> Registry {
        Registry {
            request: Request::default(),
            scheme: String::new(),
            host: String::new(),
            repo: String::new(),
        }
    }

    fn url(&self, path: &str, query: &[&str]) -> Result<String> {
        let query_str = if !query.is_empty() {
            format!("?{}", query.join("&"))
        } else {
            String::new()
        };

        let url = format!("{}://{}", self.scheme, self.host.as_str());
        let url = Url::parse(url.as_str()).map_err(ReqErr::inv_data)?;
        let path = format!("/v2/{}{}{}", self.repo, path, query_str);
        let url = url.join(path.as_str()).map_err(ReqErr::inv_input)?;

        Ok(url.to_string())
    }

    fn create_upload(&self) -> Result<String> {
        let method = "POST";

        let url = self.url("/blobs/uploads/", &[])?;

        let resp = self.request.call::<&[u8]>(
            method,
            url.as_str(),
            ReqBody::Buf(b"".to_vec()),
            HeaderMap::new(),
        )?;

        let location = resp.headers().get(HEADER_LOCATION);

        if let Some(location) = location {
            let location = location.to_str().map_err(ReqErr::inv_data)?.to_owned();
            return Ok(location);
        }

        Err(ReqErr::inv_data("location not found in header"))
    }
}

pub fn new<S: std::hash::BuildHasher>(config: &HashMap<String, String, S>) -> Result<Registry> {
    let host = config
        .get("host")
        .ok_or_else(|| ReqErr::inv_input("host required"))?;
    let repo = config
        .get("repo")
        .ok_or_else(|| ReqErr::inv_input("repo required"))?;

    let host = (*host).to_owned();
    let repo = (*repo).to_owned();

    let scheme = if let Some(scheme) = config.get("scheme") {
        (*scheme).to_owned()
    } else {
        String::from("https")
    };
    let request = Request::new(config.get("proxy"))?;

    Ok(Registry {
        request,
        scheme,
        host,
        repo,
    })
}

impl BlobBackend for Registry {
    fn read(&self, blob_id: &str, buf: &mut Vec<u8>, offset: u64, count: usize) -> Result<usize> {
        let method = "GET";

        let url = format!("/blobs/{}", blob_id);
        let url = self.url(url.as_str(), &[])?;

        let mut headers = HeaderMap::new();
        let end_at = offset + count as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.as_str().parse().map_err(ReqErr::inv_data)?);

        let mut resp = self
            .request
            .call::<&[u8]>(method, url.as_str(), ReqBody::Buf(b"".to_vec()), headers)
            .or_else(|e| {
                error!("registry req failed {:?}", e);
                Err(e)
            })?;

        resp.copy_to(buf)
            .or_else(|err| {
                error!("registry read failed {:?}", err);
                Err(ReqErr::broken_pipe(err))
            })
            .map(|size| size as usize)
    }

    fn write(&self, _blob_id: &str, _buf: &[u8], _offset: u64) -> Result<usize> {
        Ok(_buf.len())
    }

    fn close(&mut self) {}
}

impl BlobBackendUploader for Registry {
    type Reader = File;

    fn upload(
        &self,
        blob_id: &str,
        file: File,
        size: usize,
        callback: fn((usize, usize)),
    ) -> Result<usize> {
        let location = self.create_upload()?;

        let mut blob_id = blob_id.to_owned();
        if !blob_id.starts_with("sha256:") {
            blob_id = format!("sha256:{}", blob_id);
        }

        let method = "PUT";
        let url = Url::parse_with_params(location.as_str(), &[("digest", blob_id.as_str())])
            .map_err(ReqErr::inv_data)?;

        let url = format!(
            "{}://{}{}?{}",
            self.scheme,
            self.host,
            url.path(),
            url.query().unwrap()
        );

        let body = Progress::new(file, size, callback);

        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_CONTENT_LENGTH,
            size.to_string().parse().map_err(ReqErr::inv_data)?,
        );
        headers.insert(
            HEADER_CONTENT_TYPE,
            HEADER_OCTET_STREAM.parse().map_err(ReqErr::inv_data)?,
        );

        self.request
            .call(method, url.as_str(), ReqBody::Read(body, size), headers)?;

        Ok(size as usize)
    }
}
