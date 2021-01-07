#!/bin/bash

clickdir=$(realpath `pwd`)

set -e

podman build $BUILD_ARGS -f builder.dock -t click-builder .
podman run -v $clickdir:/click:Z click-builder ./build-deb.sh
