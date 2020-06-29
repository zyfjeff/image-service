// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::Result;
use url::Url;

use crate::storage::backend::request::{HeaderMap, Progress, ReqBody, Request};
use crate::storage::backend::{BlobBackend, BlobBackendUploader};

use nydus_error::{einval, epipe};

const HEADER_CONTENT_LENGTH: &str = "Content-Length";
const HEADER_CONTENT_TYPE: &str = "Content-Type";
const HEADER_LOCATION: &str = "LOCATION";
const HEADER_OCTET_STREAM: &str = "application/octet-stream";

#[derive(Debug, Default)]
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
        let path = if !query.is_empty() {
            format!("/v2/{}{}?{}", self.repo, path, query.join("&"))
        } else {
            format!("/v2/{}{}", self.repo, path)
        };
        let url = format!("{}://{}", self.scheme, self.host.as_str());
        let url = Url::parse(url.as_str()).map_err(|e| einval!(e))?;
        let url = url.join(path.as_str()).map_err(|e| einval!(e))?;

        Ok(url.to_string())
    }

    fn create_upload(&self) -> Result<String> {
        let method = "POST";
        let url = self.url("/blobs/uploads/", &[])?;

        // Safe because the the call() is a synchronous operation.
        let data = unsafe { ReqBody::from_static_slice(b"") };
        let resp = self
            .request
            .call::<&[u8]>(method, url.as_str(), data, HeaderMap::new())?;

        match resp.headers().get(HEADER_LOCATION) {
            Some(location) => Ok(location.to_str().map_err(|e| einval!(e))?.to_owned()),
            None => Err(einval!("location not found in header")),
        }
    }
}

pub fn new<S: std::hash::BuildHasher>(config: &HashMap<String, String, S>) -> Result<Registry> {
    let host = config
        .get("host")
        .map(|s| s.to_owned())
        .ok_or_else(|| einval!("host required"))?;
    let repo = config
        .get("repo")
        .map(|s| s.to_owned())
        .ok_or_else(|| einval!("repo required"))?;
    let scheme = if let Some(scheme) = config.get("scheme") {
        scheme.to_owned()
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
    fn read(&self, blob_id: &str, mut buf: &mut [u8], offset: u64) -> Result<usize> {
        let method = "GET";

        let url = format!("/blobs/{}", blob_id);
        let url = self.url(url.as_str(), &[])?;

        let mut headers = HeaderMap::new();
        let end_at = offset + buf.len() as u64 - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.as_str().parse().map_err(|e| einval!(e))?);

        // Safe because the the call() is a synchronous operation.
        let data = unsafe { ReqBody::from_static_slice(b"") };
        let mut resp = self
            .request
            .call::<&[u8]>(method, url.as_str(), data, headers)
            .or_else(|e| {
                error!("registry req failed {:?}", e);
                Err(e)
            })?;

        resp.copy_to(&mut buf)
            .or_else(|err| Err(epipe!(format!("registry read failed {:?}", err))))
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
        let method = "PUT";

        let blob_id_storage;
        let blob_id_val = if !blob_id.starts_with("sha256:") {
            blob_id_storage = format!("sha256:{}", blob_id);
            &blob_id_storage
        } else {
            blob_id
        };
        let url = Url::parse_with_params(location.as_str(), &[("digest", blob_id_val)])
            .map_err(|e| einval!(e))?;

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
            size.to_string().parse().map_err(|e| einval!(e))?,
        );
        headers.insert(
            HEADER_CONTENT_TYPE,
            HEADER_OCTET_STREAM.parse().map_err(|e| einval!(e))?,
        );

        self.request
            .call(method, url.as_str(), ReqBody::Read(body, size), headers)?;

        Ok(size as usize)
    }
}
