# nydus-rs
A container image acceleration tool.

# Howto run it?

```
./nydusd --config config.json --metadata bootstrap --sock vhost-user-fs.sock
```

where the `config.json` is of format like:

oss backend:
```
{
  "device_config": {
    "backend_type": "oss",
    "backend_config": "endpoint=,access_key_id=,access_key_secret=,bucket_name="
  }
}
```

registry backend:
```
{
  "device_config": {
    "backend_type": "registry",
    "backend_config": "host=,repo="
  }
}
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

# Build nydus image

See [Nydus Image Builder](./docs/image-builder.md) 
