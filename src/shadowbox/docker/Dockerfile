# Copyright 2018 The Outline Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Use the existing NODE_IMAGE that is pinned to the Alpine-based Node.js image
ARG NODE_IMAGE
FROM ${NODE_IMAGE}
ARG VERSION

LABEL shadowbox.node_version=16.18.0
LABEL shadowbox.github.release=${VERSION}

# The user management service doesn't quit with SIGTERM.
STOPSIGNAL SIGKILL

# Install necessary packages using Alpine's package manager 'apk'
RUN apk add --no-cache coreutils curl iproute2 gnupg

# Manually download and install Cloudflare WARP for Alpine
RUN curl -LO https://pkg.cloudflareclient.com/releases/cloudflare-warp-linux-x86_64.tgz \
    && tar -xvzf cloudflare-warp-linux-x86_64.tgz \
    && cp cloudflare-warp-linux-x86_64/warp-cli /usr/local/bin/ \
    && rm -rf cloudflare-warp-linux-x86_64*

# Register Cloudflare WARP
RUN warp-cli register
RUN warp-cli set-mode proxy

# Copy project files into the container
COPY . /

# Update MMDB databases
RUN /etc/periodic/weekly/update_mmdb.sh

# Set working directory
WORKDIR /opt/outline-server

# Ensure WARP connects on container startup and run the Outline server
CMD warp-cli connect && /cmd.sh
