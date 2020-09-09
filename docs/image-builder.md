# Nydus Image Builder

Nydus image contains two parts, `bootstrap` and `blob`:

- `bootstrap` records the file inode and the index of data chunk in rootfs;
- `blob` packs all compressed file data chunk in rootfs;

Nydus image builder is used to building the existing container rootfs directory into the `bootstrap` and `blob` file required by nydusd.

[Buildkitd](https://gitlab.alibaba-inc.com/kata-containers/buildkit) provides a script tool to convert oci image to nydus format image using `bootstrap` and upload `blob` file to storage backend (for example aliyun OSS, docker registry).

## Compile nydus image builder

```shell
cargo build --release
```

## Build nydus image from directory source

```shell
# $BLOB_PATH: output blob file path, optional
# $BLOB_ID: blob id for storage backend, optional
# $BOOTSTRAP_PATH: output bootstrap file path
# $PARENT_BOOTSTRAP_PATH: parent bootstrap file path, optional
# $SOURCE: rootfs source directory path
# $BACKEND_TYPE: oss | registry | localfs, optional
# $BACKEND_CONFIG: JSON string of backend config, optional

./target/release/nydus-image create \
            --blob $BLOB_PATH \
            --blob-id $BLOB_ID \
            --bootstrap $BOOTSTRAP_PATH \
            --parent-bootstrap $PARENT_BOOTSTRAP_PATH \
            --backend-type $BACKEND_TYPE \
            --backend-config $BACKEND_CONFIG \
            --repeatable \
            $SOURCE
```

For `localfs` backend, it's much simpler as below:

```shell
./target/release/nydus-image create \
            --bootstrap $BOOTSTRAP_PATH \
            --backend-type localfs \
            --backend-config "{\"dir\":\"/path/to/blobs/\"}" \
            $SOURCE
```

An example of JSON string of $BACKEND_CONFIG,

oss backend,
```shell
--backend_config '{"endpoint":"region.aliyuncs.com","access_key_id":"","access_key_secret":"","bucket_name":""}'
```

registry backend,

```shell
--backend_config '{"scheme":"https","host":"my-registry:5000","repo":"test/repo","auth":"<base64_encoded_auth>"}'
```

## Build nydus image from stargz index

### Stargz build

```shell
nydus-image create --source-type stargz_index --bootstrap <parent-bootstrap-path> --blob-id <image-lower-layer-id> --log-level trace <stargz.index-lower.json>
```

### Stargz layered build:

```shell
nydus-image create --source-type stargz_index --parent-bootstrap <parent-bootstrap-path> --bootstrap <bootstrap-path> --blob-id <image-upper-layer-id> --log-level trace <stargz.index-upper.json>
```

Note: the argument value of image layer id specified in nydus-image CLI should omit `sha256:` prefix.
