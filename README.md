# nydus-rs
A container image acceleration tool.

# Build binary

`make` or `make release`

# Run nydusd

```
./nydusd --config config.json --metadata bootstrap --sock vhost-user-fs.sock
```

where the `config.json` is of format like:

oss backend with blobcache:
```
{
  "device_config": {
    "backend": {
      "type": "oss",
      "config": {
        "endpoint": "region.aliyuncs.com",
        "access_key_id": "",
        "access_key_secret": "",
        "bucket_name": ""
      }
    },
    "cache": {
      "type": "blobcache",
      "config": {
        "work_dir": "/cache"
      }
    }
  }
}
```

registry backend:
```
{
  "device_config": {
    "backend": {
      "type": "registry",
      "config": {
        "host": "user:pass@my-registry:5000",
        "repo": ""
      }
    }
  }
}
```

localfs backend:
```
{
  "device_config": {
    "backend": {
      "type": "localfs",
      "config": {
        "dir": "/path/to/blobs/"
      }
    },
    "cache": {}
  }
}
```

To mount a bootstrap via api, first launch nydusd without a bootstrap:
```
./nydusd --apisock api.sock --config config.json --sock vhost-user-fs.sock
```

Then use curl to call the mount api:
```
curl --unix-socket api.sock \
     -X PUT "http://localhost/api/v1/mount" -H "accept: */*" \
     -H "Content-Type: application/json" \
     -d "{\"source\":\"<path-to-bootstrap>\",\"fstype\":\"rafs\",\"mountpoint\":\"/foo/bar\"}"
```

To start a qemu process, run something like:
```
./qemu-system-x86_64 -M pc -cpu host --enable-kvm -smp 2 \
        -m 2G,maxmem=16G -object memory-backend-file,id=mem,size=2G,mem-path=/dev/shm,share=on -numa node,memdev=mem \
        -chardev socket,id=char0,path=/home/graymalkin/tests/nydus/foo.sock \
        -device vhost-user-fs-pci,chardev=char0,tag=nydus,queue-size=1024,indirect_desc=false,event_idx=false \
        -serial mon:stdio -vga none -nographic -curses -kernel ./kernel \
        -append 'console=ttyS0 root=/dev/vda1 virtio_fs.dyndbg="+pfl" fuse.dyndbg="+pfl"' \
        -device virtio-net-pci,netdev=net0,mac=AE:AD:BE:EF:6C:FB -netdev type=user,id=net0 \
        -qmp unix:/home/graymalkin/tests/nydus/qmp.sock,server,nowait \
        -drive if=virtio,file=./bionic-server-cloudimg-amd64.img
```

Then we can mount nydus virtio-fs inside the guest with:
```
mount -t virtio_fs none /mnt -o tag=nydus,default_permissions,allow_other,rootmode=040000,user_id=0,group_id=0,nodev
```
Or simply below if you are running newer guest kernel:
```
mount -t virtiofs nydus /mnt
```

# Multiple pseudo mounts
One single nydusd can have multiple pseudo mounts corresponding to a unique virtio-fs mount inside guest.

To obtain that, you have to trigger backend fs(e.g. Rafs) mount through curl method. Please note that don't specify
`--metadata` option when you start nydusd.

The steps are exactly the same with one nydusd one backend fs scenario. But before any curl mount, you can't see
any data from the virtio-fs mount inside guest.
Then each time you do mount through curl command, you have a sub-directory created automatically within the virtio-fs mount point where you could find image data.

Example:<br>
Given that your virtio-fs mount point is `/mnt` inside guest.<br>
When you have two pseudo mounts which are named as "pseudo_1" and "pseudo_2" identified in http request data.<br>
pseudo_1 and pseudo_2 corresponds to bootstrap respectively.
```
# tree -L 1 mnt
mnt
├── pseudo_1
└── pseudo_2
```

# Build nydus image

See [Nydus Image Builder](./docs/image-builder.md) 
