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

## Build nydus image from source

```shell
# $BLOB_PATH: blob file path, optional
# $BLOB_ID: blob id for storage backend
# $BOOTSTRAP_PATH: bootstrap file path
# $PARENT_BOOTSTRAP_PATH: parent bootstrap file path, optional
# $SOURCE: rootfs source directory
# $BACKEND_TYPE: oss|registry
# $BACKEND_CONFIG: JSON string

./target/release/nydus-image create \
            --blob $BLOB_PATH \
            --blob_id $BLOB_ID \
            --bootstrap $BOOTSTRAP_PATH \
            --parent_bootstrap $PARENT_BOOTSTRAP_PATH \
            --backend_type $BACKEND_TYPE \
            --backend_config $BACKEND_CONFIG \
            $SOURCE
```
