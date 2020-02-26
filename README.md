# nydus-rs
A container image acceleration tool.

# Howto run it?

```
./nydusd --config config.json --metadata bootstrap --sock vhost-user-fs.sock
```

where the `config.json` is of format like:
```
{
  "device_config": {
    "backend_type": "oss",
    "endpoint": "alibaba-cloud-oss-endpoint",
    "bucket_name": "name",
    "access_key_id": "id",
    "access_key_secret": "secret"
  }
}
```
