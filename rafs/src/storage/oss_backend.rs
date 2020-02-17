use std::time::SystemTime;

use base64;
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use httpdate;
use reqwest::{self, header::HeaderMap, StatusCode};
use std::collections::HashMap;
use std::io::Result as IOResult;
use std::io::{Error, ErrorKind};
use std::io::{Read, Write};
use url::Url;

use crate::storage::backend::BlobBackend;
use fuse::filesystem::{ZeroCopyReader, ZeroCopyWriter};

const HEADER_DATE: &str = "Date";
const HEADER_AUTHORIZATION: &str = "Authorization";

pub struct OSS {
    access_key_id: String,
    access_key_secret: String,
    endpoint: String,
    bucket_name: String,
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

        let authorization = format!("OSS {}:{}", self.access_key_id, signature);
        return authorization;
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

// pub fn new(config: HashMap<&str, &str>) -> OSS {
//   let endpoint = config.get("endpoint").unwrap();
//   let access_key_id = config.get("access_key_id").unwrap();
//   let access_key_secret = config.get("access_key_secret").unwrap();
//   let bucket_name = config.get("bucket_name").unwrap();
//   OSS {
//       endpoint: (*endpoint).to_owned(),
//       access_key_id: (*access_key_id).to_owned(),
//       access_key_secret: (*access_key_secret).to_owned(),
//       bucket_name: (*bucket_name).to_owned(),
//   }
// }

impl OSS {
    fn init(&self, _config: HashMap<&str, &str>) -> IOResult<()> {
        return self.create_bucket(self.bucket_name.as_str());
    }
    fn add(&mut self, _blob_id: &str) -> IOResult<()> {
        Ok(())
    }
    fn delete(&mut self, object_key: &str) -> IOResult<()> {
        let headers = HeaderMap::new();
        self.request(
            "DELETE",
            "",
            self.bucket_name.as_str(),
            object_key,
            headers,
            &[],
        )?;
        Ok(())
    }
    fn read_to<W: Write + ZeroCopyWriter>(
        &self,
        mut writer: W,
        blob_id: &str,
        count: usize,
        offset: u64,
    ) -> IOResult<usize> {
        let mut headers = HeaderMap::new();
        let end_at = offset + (count as u64) - 1;
        let range = format!("bytes={}-{}", offset, end_at);
        headers.insert("Range", range.as_str().parse().unwrap());
        let mut resp = self.request("GET", "", self.bucket_name.as_str(), blob_id, headers, &[])?;
        let ret = resp.copy_to(&mut writer);
        match ret {
            Ok(size) => Ok(size as usize),
            Err(err) => Err(Error::new(ErrorKind::Other, format!("{}", err))),
        }
    }
    fn write_from<R: Read + ZeroCopyReader>(
        &self,
        reader: R,
        blob_id: &str,
        count: usize,
        offset: u64,
    ) -> IOResult<usize> {
        let headers = HeaderMap::new();
        let position = format!("position={}", offset);
        let mut vec = Vec::new();
        reader.take(count as u64).read_to_end(&mut vec)?;
        self.request(
            "POST",
            vec,
            self.bucket_name.as_str(),
            blob_id,
            headers,
            &["append", position.as_str()],
        )?;
        Ok(count)
    }
    fn close(&mut self) {}
}

impl BlobBackend for OSS {
    fn init(&mut self, _config: HashMap<&str, &str>) -> IOResult<()> {
        Ok(())
    }

    // Read a range of data from blob into the provided destination
    fn read(&self, _blobid: &str, buf: &mut Vec<u8>, _offset: u64) -> IOResult<usize> {
        Ok(buf.len())
    }

    // Write a range of data to blob from the provided source
    fn write(&self, _blobid: &str, buf: &Vec<u8>, _offset: u64) -> IOResult<usize> {
        Ok(buf.len())
    }

    fn close(&mut self) {}
}
