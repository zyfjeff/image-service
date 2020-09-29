// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use]
extern crate log;

pub mod binary_resource;
pub mod fd_resource;
pub mod resource;

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

use binary_resource::backend::BackendType;
use binary_resource::BinaryResource;
use fd_resource::FdResource;
use resource::{ResourceName, ResourceWrapper};

#[derive(Default)]
pub struct UpgradeManager {
    id: String,
    resources: HashMap<ResourceName, Box<dyn ResourceWrapper + Sync + Send + 'static>>,
}

impl UpgradeManager {
    pub fn new(id: String) -> Self {
        UpgradeManager {
            id,
            ..Default::default()
        }
    }

    pub fn add_binary_resource(&mut self, res_name: ResourceName) {
        let key = format!("{}_{}_{}", self.id, "resource", res_name);
        let res = BinaryResource::new(key.as_str(), BackendType::default()).unwrap();
        self.resources.insert(res_name, Box::new(res));
    }

    pub fn add_fd_resource(&mut self, res_name: ResourceName, supervisor: String, fds: Vec<RawFd>) {
        let res = FdResource::new(PathBuf::from(supervisor), fds);
        self.resources.insert(res_name, Box::new(res));
    }

    pub fn get_resource<R>(&mut self, res_name: ResourceName) -> Option<&mut R>
    where
        R: ResourceWrapper + Sync + Send + 'static,
    {
        if let Some(res) = self.resources.get_mut(&res_name).map(|r| r.as_mut()) {
            return res.as_any().downcast_mut::<R>();
        }
        None
    }

    pub fn del_resource(&mut self, res_name: ResourceName) {
        self.resources.remove(&res_name);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Result;

    use super::*;

    use binary_resource::tests::{Test, TestArgs};
    use binary_resource::BinaryResource;
    use resource::Resource;

    #[test]
    fn test_upgrade_manager_with_binary_resource_with_empty_data() {
        // Save the binary resource to upgrade manager
        let mut mgr = UpgradeManager::new("nydus-smoke-test-1".to_string());

        mgr.add_binary_resource(ResourceName::RafsConf);

        // Get the binary resource from upgrade manager
        let resource: &mut BinaryResource = mgr.get_resource(ResourceName::RafsConf).unwrap();

        // Restore should be failed for the backend has no data
        assert!((resource.restore(TestArgs { baz: 10 }) as Result<Test>).is_err());
    }

    #[test]
    fn test_upgrade_manager_with_binary_resource() {
        let foo = HashMap::new();
        let test = Test {
            foo: foo.clone(),
            bar: String::from("bar"),
            baz: 100,
        };

        // Save the binary resource to upgrade manager
        let mut mgr = UpgradeManager::new("nydus-smoke-test-2".to_string());

        mgr.add_binary_resource(ResourceName::RafsConf);

        // Get the binary resource from upgrade manager
        let resource: &mut BinaryResource = mgr.get_resource(ResourceName::RafsConf).unwrap();

        // Save an object to binary resource
        resource.save(&test).unwrap();

        // Restore the object from binary resource
        let expected = Test {
            foo,
            bar: String::from("bar"),
            baz: 10,
        };
        let restored_test: Test = resource.restore(TestArgs { baz: 10 }).unwrap();

        resource.destroy().unwrap();

        assert_eq!(restored_test, expected);
    }
}
