# Nydus Image Builder

Nydus image contains two parts, `bootstrap` and `blob`:

- `bootstrap` records the file inode and the index of data chunk in rootfs;
- `blob` packs all compressed file data chunk in rootfs;

Nydus image builder is used to building the existing container rootfs directory into the `bootstrap` and `blob` file required by nydusd.

[Buildkitd](https://gitlab.alibaba-inc.com/kata-containers/buildkit) provides a script tool to convert oci image to nydus format image using `bootstrap` and upload `blob` file to storage backend (for example aliyun OSS).

## Compile nydus image builder

```shell
cargo build --release
```

## Build nydus image from source

```shell
# $BLOB_PATH: blob file path, optional
# $BLOB_ID: blob id for storage backend
# $BOOTSTRAP_PATH: bootstrap file path
# $SOURCE: rootfs source directory
# $OSS_*: aliyun oss config

./target/release/nydus-image create \
            --blob $BLOB_PATH \
            --blob_id $BLOB_ID \
            --bootstrap $BOOTSTRAP_PATH \
            --oss_endpoint $OSS_ENDPOINT \
            --oss_access_key_id $OSS_ACCESS_KEY_ID \
            --oss_access_key_secret $OSS_ACCESS_KEY_SECRET \
            --oss_bucket_name $OSS_BUCKET_NAME \
            $SOURCE
```
