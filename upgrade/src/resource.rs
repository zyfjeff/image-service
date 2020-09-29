// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::fmt;
use std::io::Result;

use snapshot::Persist;
use versionize::{VersionMap, Versionize};

use super::binary_resource::BinaryResource;
use super::fd_resource::FdResource;

// Use ResourceName to distinguish resource instances in
// UpgradeManager, you can add more as you need.
#[derive(Hash, PartialEq, Eq)]
pub enum ResourceName {
    FuseDevFd,
    RafsConf,
}

impl fmt::Display for ResourceName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::FuseDevFd => write!(f, "fuse_dev_fd"),
            Self::RafsConf => write!(f, "rafs_conf"),
        }
    }
}

pub trait Resource {
    fn save<'a, O, V, D>(&mut self, obj: &O) -> Result<()>
    where
        O: Persist<'a, State = V, Error = D>,
        V: Versionize + VersionMapGetter,
        D: std::fmt::Debug;

    fn restore<'a, O, V, A, D>(&mut self, args: A) -> Result<O>
    where
        O: Persist<'a, State = V, ConstructorArgs = A, Error = D>,
        V: Versionize + VersionMapGetter,
        D: std::fmt::Debug;
}

pub trait ResourceWrapper {
    fn as_any(&mut self) -> &mut dyn Any;
}

impl ResourceWrapper for FdResource {
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

impl ResourceWrapper for BinaryResource {
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

// Use version map to mange resource version during serializing/deserializing,
// here is a default implementation, returns the version map with only one version,
// If you need to add a version 2 for resource, need to do like this:
// `VersionMap::new().new_version().set_type_version(Self::type_id(), 2).clone()`
pub trait VersionMapGetter {
    fn version_map() -> VersionMap {
        VersionMap::new()
    }
}
