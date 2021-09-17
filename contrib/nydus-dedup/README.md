# Nydus deduplication tools
## Introduction
Nydus deduplication tools includes a series of utilities related to Nydus.

This project mainly includes the following parts:

* Nydus Dump
* Ociv1 Dump
* Nydus Stat

## Usage
* **./nydus-dump.sh [ConfigureFile]**

* **./ociv1-dump.sh [ConfigureFile]**

* **./nydus-stat [DirectoryName]**

## Getting Started

### Nydus Dump

``` shell
# We provide some example lists in the "nydus-stat/data/example" directory,
# or you can get the chunk lists by nydus-dump manually.
```

1. Download or build modified Nydus binary.
``` shell
# Build modified nydus-rs binary
git clone git@gitlab.alibaba-inc.com:kata-containers/nydus-rs.git
cd nydus-rs
git checkout nydus-dedup/v1.6.1
make release
cd contrib/nydusify
make
# Put 3 binary files into the "nydus-dump/bin" directory.
# Incuding nydusd nydusify nydus-image.
chmod +x bin/
```

2. Start local registry or online registry (such as Docker Hub or ACR).
``` shell
docker run -d \
  -p 5000:5000 \
  --restart=always \
  --name registry \
  -v /opt/registry:/var/lib/registry \
  registry:2
```

3. Configure environment
``` shell
cd nydus-dump
vi conf/example.conf
``` 

4. Run Nydus Dump.
``` shell
chmod +x nydus-dump.sh
sudo ./nydus-dump.sh conf/example.conf
``` 

5. View generated chunk lists.
``` shell
# Replace with your own image namespace.
cd output/example
ls
```

### Ociv1 Dump
1. Install Docker and Dive.

2. Configure environment
``` shell
cd ociv1-dump
vi conf/example.conf
``` 

3. Run Ociv1 Dump.
``` shell
chmod +x ociv1-dump.sh
./ociv1-dump.sh conf/example.conf
``` 

4. View dumps image list.
``` shell
# Replace with your own image namespace.
cd output/example
ls
```

### Nydus Stat

1. Build binary.

``` shell
# Build with Cmake version 3.1 or higher.

cd nydus-stat
mkdir build
cd build
cmake ..  # It may also be cmake3 ..
make
```

2. Run Nydus Stat.

``` shell
# If you want to analyze the previously generated chunk list, 
# you need to replace "data/example" with the corresponding directory.

mv nydus-stat ../
cd ..
./nydus-stat data/example
```
3. View result.