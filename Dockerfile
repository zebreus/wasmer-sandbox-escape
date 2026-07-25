FROM ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb
ENV DEBIAN_FRONTEND=noninteractive

# install some random dependencies
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git xz-utils build-essential cmake pkg-config python3 libssl-dev zlib1g-dev libzstd-dev libxml2-dev libncurses-dev libffi-dev libedit-dev

# install wasmer (7.2.1 is tested but I don't know how to pin the version)
RUN curl https://get.wasmer.io -sSfL | sh
RUN ln -s /root/.wasmer/bin/wasmer /usr/bin/wasmer
RUN ln -s /root/.wasmer/bin/wasmer-headless /usr/bin/wasmer-headless
ENV WASMER_DIR="/root/.wasmer"
ENV WASMER_CACHE_DIR="/root/.wasmer/cache"

# copy the poc into the container
COPY poc /poc