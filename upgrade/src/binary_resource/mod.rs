// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

pub mod backend;

use std::io::Result;

use snapshot::{Persist, Snapshot};
use versionize::Versionize;

use super::resource::{Resource, VersionMapGetter};
use backend::shared_memory::SharedMemoryBackend;
use backend::{Backend, BackendType};
use nydus_utils::einval;

// BinaryResource is responsible for saving (serialized to binary data) to storage backend
// and restoring state (deserialized from binary data) from storage backend.
pub struct BinaryResource {
    backend: Box<dyn Backend>,
}

impl BinaryResource {
    pub fn new(name: &str, backend_type: BackendType) -> Result<Self> {
        let backend = match backend_type {
            BackendType::SharedMemory => Box::new(SharedMemoryBackend::new(name)?),
        };
        Ok(Self { backend })
    }

    pub fn destroy(&mut self) -> Result<()> {
        self.backend.destroy()
    }
}

impl Resource for BinaryResource {
    fn save<'a, O, V, D>(&mut self, obj: &O) -> Result<()>
    where
        O: Persist<'a, State = V, Error = D>,
        V: Versionize + VersionMapGetter,
        D: std::fmt::Debug,
    {
        let vm = V::version_map();
        let latest_version = vm.latest_version();

        let mut snapshot = Snapshot::new(vm, latest_version);

        let state = obj.save();

        snapshot
            .save_with_crc64(&mut self.backend.writer()?, &state)
            .map_err(|e| einval!(e))?;

        self.backend.reset()
    }

    fn restore<'a, O, V, A, D>(&mut self, args: A) -> Result<O>
    where
        O: Persist<'a, State = V, ConstructorArgs = A, Error = D>,
        V: Versionize + VersionMapGetter,
        D: std::fmt::Debug,
    {
        let vm = V::version_map();

        let restored = Snapshot::load_with_crc64(&mut self.backend.reader()?, vm).map_err(|e| {
            warn!("binary resource: failed to restore from backend: {}", e);
            einval!(e)
        })?;

        O::restore(args, &restored).map_err(|e| einval!(e))
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;
    use std::io::Error;

    use snapshot::Persist;
    use versionize::VersionMap;
    use versionize::{Versionize, VersionizeResult};
    use versionize_derive::Versionize;

    use super::*;
    use crate::resource::{Resource, VersionMapGetter};

    #[derive(Clone, Debug, PartialEq)]
    pub struct Test {
        pub foo: HashMap<String, String>,
        pub bar: String,
        pub baz: u32,
    }

    #[derive(Clone, Debug, Versionize)]
    pub struct TestState {
        foo: HashMap<String, String>,
        #[version(start = 2, default_fn = "bar_default")]
        bar: String,
        baz: u32,
    }

    impl TestState {
        fn bar_default(_: u16) -> String {
            String::from("bar")
        }
    }

    impl VersionMapGetter for TestState {
        fn version_map() -> VersionMap {
            VersionMap::new()
                .new_version()
                .set_type_version(Self::type_id(), 2)
                .clone()
        }
    }

    pub struct TestArgs {
        pub baz: u32,
    }

    impl Persist<'_> for Test {
        type State = TestState;
        type ConstructorArgs = TestArgs;
        type Error = Error;

        fn save(&self) -> Self::State {
            TestState {
                foo: self.foo.clone(),
                bar: self.bar.clone(),
                baz: self.baz,
            }
        }

        fn restore(
            args: Self::ConstructorArgs,
            state: &Self::State,
        ) -> std::result::Result<Self, Self::Error> {
            Ok(Test {
                foo: state.foo.clone(),
                bar: state.bar.clone(),
                baz: args.baz,
            })
        }
    }

    #[test]
    fn test_binary_resource() {
        // Save an object
        let mut foo = HashMap::new();
        foo.insert(String::from("abc"), String::from("def"));

        let test = Test {
            foo: foo.clone(),
            bar: String::from("bar"),
            baz: 100,
        };

        let mut binary_resource =
            BinaryResource::new("nydus-binary-resource-test", BackendType::default()).unwrap();

        // Clean shared memory file first
        binary_resource.destroy().unwrap();

        binary_resource.save(&test).unwrap();

        // Restore the object
        let expected = Test {
            foo,
            bar: String::from("bar"),
            baz: 10,
        };

        let restored_test: Test = binary_resource.restore(TestArgs { baz: 10 }).unwrap();

        binary_resource.destroy().unwrap();

        assert_eq!(restored_test, expected);
    }
}
