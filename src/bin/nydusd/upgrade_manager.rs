// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::collections::HashMap;
use std::io::Result;
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
    fn load(&self) -> Result<()>;
    fn store(&self) -> Result<()>;
    fn as_any(&self) -> &dyn Any;
}
