#!/bin/sh

set -eu

# waiting dockerd ready
timeout=30
while [ ${timeout} -gt 0 ]; do
       if docker ps >/dev/null 2>&1; then
               echo "dockerd is ready"
               break
       fi
       echo "waiting dockerd ready, timeout=${timeout}s"
       sleep 1
       timeout=$((timeout-1))
done

if [ ${timeout} -lt 0 ]; then
       echo "dockerd not ready, timed out 30s."
       exit 1
fi

# start registry
docker run -d --restart=always -p 5000:5000 registry

# prepare nydus image
NYDUS_IMAGE=/opt/bin/nydus-image
SOURCE_IMAGE=busybox
TARGET_IMAGE=localhost:5000/busybox-nydus
/opt/bin/nydusify convert --nydus-image $NYDUS_IMAGE --source $SOURCE_IMAGE --target $TARGET_IMAGE

# run a container with nydus image
crictl run container-config.yaml pod-config.yaml

sleep 3

cid=$(crictl ps --name nydus-container -q)
echo "The test container id: $cid"

# Do a simple test
echo "Do a simple test in container: ls /"
crictl exec $cid ls /
if [ $? -ne 0 ]; then
	echo "Failed to `ls /` in container, please check"
	exit 1
fi
