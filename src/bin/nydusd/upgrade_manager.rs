// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::sync::{Arc, Mutex};

lazy_static! {
    pub static ref UPGRADE_MGR: Mutex<UpgradeManager> = Mutex::new(UpgradeManager::new());
}
#[derive(Default)]
pub struct UpgradeManager {
    resources: HashMap<ResourceType, Arc<dyn Resource + Sync + Send>>,
}

#[derive(Hash, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ResourceType {
    Fd,
    Binary,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum UpgradeManagerError {
    NoResource,
    NotReady,
    Connect(io::Error),
    SendFd,
    RecvFd,
    Disconnect(io::Error),
}

impl Display for UpgradeManagerError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub type UpgradeManagerResult<T> = std::result::Result<T, UpgradeManagerError>;

#[allow(dead_code)]
impl UpgradeManager {
    fn new() -> Self {
        UpgradeManager {
            ..Default::default()
        }
    }

    pub fn add_resource<R: Resource + Sync + Send + 'static>(&mut self, r: R, t: ResourceType) {
        if self.resources.insert(t, Arc::new(r)).is_some() {
            debug!("Already exists");
        }
    }

    pub fn get_resource(&self, t: ResourceType) -> Option<&(dyn Resource + Send + Sync)> {
        self.resources.get(&t).map(|r| r.as_ref())
    }

    pub fn del_resource(&mut self, _res: String) {}
}

pub trait Resource {
    fn load(&self) -> UpgradeManagerResult<()>;
    fn store(&self) -> UpgradeManagerResult<()>;
    fn as_any(&self) -> &dyn Any;
}
