// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use]
extern crate log;

#[allow(dead_code)]
pub mod binary_resource;
#[allow(dead_code)]
pub mod fd_resource;
pub mod resource;

#[macro_use]
extern crate lazy_static;

use resource::{ResourceType, ResourceWrapper};
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static! {
    pub static ref UPGRADE_MGR: Mutex<UpgradeManager> = Mutex::new(UpgradeManager::new());
}

#[derive(Default)]
pub struct UpgradeManager {
    resources: HashMap<ResourceType, Box<dyn ResourceWrapper + Sync + Send + 'static>>,
}

impl UpgradeManager {
    fn new() -> Self {
        UpgradeManager {
            ..Default::default()
        }
    }

    pub fn add_resource<R: ResourceWrapper + Sync + Send + 'static>(
        &mut self,
        res_type: ResourceType,
        res: R,
    ) {
        self.resources.insert(res_type, Box::new(res));
    }

    pub fn get_resource<R>(&mut self, res_type: ResourceType) -> Option<&mut R>
    where
        R: ResourceWrapper + Sync + Send + 'static,
    {
        if let Some(res) = self.resources.get_mut(&res_type).map(|r| r.as_mut()) {
            return res.as_any().downcast_mut::<R>();
        }
        None
    }

    pub fn del_resource(&mut self, res_type: ResourceType) {
        self.resources.remove(&res_type);
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
        // Save a binary resource to upgrade manager
        let mut mgr = UPGRADE_MGR.lock().unwrap();

        let key = "nydus-upgrade-manager-with-binary-resource-with-empty-data-test";
        let binary_resource = BinaryResource::new(key, None).unwrap();

        mgr.add_resource(ResourceType::RafsBinary, binary_resource);

        // Get the binary resource from upgrade manager
        let resource: &mut BinaryResource = mgr.get_resource(ResourceType::RafsBinary).unwrap();

        // Should be restore failed for the backend has no data
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

        // Save a binary resource to upgrade manager
        let mut mgr = UPGRADE_MGR.lock().unwrap();

        let mut binary_resource =
            BinaryResource::new("nydus-upgrade-manager-with-binary-resource-test", None).unwrap();

        binary_resource.destroy().unwrap();

        mgr.add_resource(ResourceType::RafsBinary, binary_resource);

        // Get the binary resource from upgrade manager
        let resource: &mut BinaryResource = mgr.get_resource(ResourceType::RafsBinary).unwrap();

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
