#!/bin/bash

# Copyright 2021 Ant Group. All rights reserved.
# Copyright (C) 2021 Alibaba Cloud. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0

# # Check sudo
# if [ "$(whoami)" != "root" ];then
# 	echo "Please re-run $(basename "$0") as root."
# 	exit 1;
# fi

# Check argument
if [ $# -ne 1 ]; then
	echo "Usage: ./ociv1-dump [ConfigureFile]"
	echo "Example: ./ociv1-dump conf/example.conf"
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

echo "Ociv1 Image Layer Dump Tools"

# Main program
overall_count=0
imagelist=$(cat "$IMAGELIST_PATH")
for line in ${imagelist}; do
	# Generate path
	((overall_count++))
	image_name=$(echo "$line" | awk '{split($0,arr,"/"); print arr[3]}')
	images_path=$(echo "$image_name" | awk '{split($0,arr,":"); print arr[1]"/"arr[2]}')
	target="$ACR_DOMAIN/$CONF_NAMESPACE/$image_name"
	log_name=$(echo "$image_name" | awk '{split($0,arr,":"); print arr[1]"_"arr[2]}')

	# Print image info
	echo ---------
	echo "Index: $overall_count"
	echo "Image name: $image_name"
	echo "Source: $line"
	echo "Target: $target"
	echo ---------

	docker pull "$line"

	mkdir -p ./output/"$CONF_NAMESPACE"/ociv1
	docker inspect --format='{{json .RootFS.Layers}}' "$line" | jq '.[]' >temp.json
	awk -F"\"" '/".*"/ {gsub("sha256:","",$2); print $1$2$3}' temp.json >./output/"$CONF_NAMESPACE"/ociv1/"$log_name".txt
	rm temp.json

	mkdir -p ./output/"$CONF_NAMESPACE"/ociv1_dive
	dive "$line" -j ./output/"$CONF_NAMESPACE"/ociv1_dive/"$log_name".json
done

echo ------------------
echo "Success dump count: $overall_count"
echo ------------------
