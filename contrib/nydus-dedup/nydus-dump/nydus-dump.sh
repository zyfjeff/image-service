#!/bin/bash

# Copyright 2021 Ant Group. All rights reserved.
# Copyright (C) 2021 Alibaba Cloud. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0

# Check sudo
if [ "$(whoami)" != "root" ]; then
	echo "Please re-run $(basename "$0") as root."
	exit 1
fi

# Check argument
if [ $# -ne 1 ]; then
	echo "Usage: ./nydus-dump.sh [ConfigureFile]"
	echo "Example: ./nydus-dump.sh conf/example.conf"
	exit 1
fi

# Check configuration file exist
configuration_file="$1"
if test -f "$configuration_file"; then
	# shellcheck source=/dev/null
	. "$configuration_file"
else
	echo "No such file or directory"
	exit 1
fi

echo "Nydus Image Chunk Dump Tools"

# Main program
overall_count=0
faild_count=0
imagelist=$(cat "$IMAGELIST_PATH")
for line in ${imagelist}; do
	# Generate path
	((overall_count++))
	image_name=$(echo "$line" | awk '{split($0,arr,"/"); print arr[3]}')
	images_path=$(echo "$image_name" | awk '{split($0,arr,":"); print arr[1]"/"arr[2]}')
	target="$ACR_DOMAIN/$ACR_NAMESPACE/$image_name"
	log_name=$(echo "$image_name" | awk '{split($0,arr,":"); print arr[1]"_"arr[2]}')

	# Print image info
	echo ---------
	echo "Index: $overall_count"
	echo "Image name: $image_name"
	echo "Source: $line"
	echo "Target: $target"
	echo ---------

	# Create directory for each image, in order to dump bootstrap and blob in /tmp directory.
	mkdir -p ./images/"$images_path"
	cd ./images/"$images_path" || return

	# Download ociv1 image, transfer to Nydus image, and upload.
	sudo "../../../$NYDUSIFY_PATH" convert --nydus-image "../../../$NYDUS_IMAGE_PATH" --source "$line" --target "$target"

	# Call modified Nydusd to dump chunk hashs.
	# shellcheck disable=SC2010
	last_bootsrap=$(ls -lt ./tmp/bootstraps | grep sha256 | grep -v json | head -n 1 | awk '{print $9}')
	mkdir -p ./mnt
	nohup sudo "../../../$NYDUSD_PATH" --config "../../../$REGISTRY_JSON_PATH" --mountpoint ./mnt --bootstrap ./tmp/bootstraps/"$last_bootsrap" --log-level info &

	# Wait for Nydusd to generate logs
	((sleep_time = 0))
	while [ ! -f ./log.txt ]; do
		sleep 1
		((sleep_time++))
		if ((sleep_time > 300)); then
			((faild_count++))
			break
		fi
	done
	sudo killall nydusd

	# Move log to data directory
	mkdir -p ../../../output/"$ACR_NAMESPACE"/nydus
	mkdir -p ../../../output/"$ACR_NAMESPACE"/nydus_new
	mv log.txt ../../../output/"$ACR_NAMESPACE"/nydus/"$log_name".txt
	mv log2.txt ../../../output/"$ACR_NAMESPACE"/nydus_new/"$log_name".txt

	cd ../../../
done

echo "------------------"
echo "Overall count: $overall_count"
echo "Faild count: $faild_count"
echo "------------------"
