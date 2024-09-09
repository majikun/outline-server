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

ARG NODE_IMAGE

FROM ${NODE_IMAGE}
ARG VERSION

# Save metadata on the software versions we are using.
LABEL shadowbox.node_version=16.18.0

LABEL shadowbox.github.release=${VERSION}

# The user management service doesn't quit with SIGTERM.
STOPSIGNAL SIGKILL

# We use curl to detect the server's public IP. We need to use the --date option in `date` to
# safely grab the ip-to-country database.
RUN apk add --no-cache --upgrade coreutils curl iproute2 gnupg lsb-release

# Add Cloudflare WARP repository and install the client
RUN curl https://pkg.cloudflareclient.com/pubkey.gpg | tee /etc/apt/trusted.gpg.d/cloudflare-warp.asc \
    && echo "deb http://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list \
    && apt-get update && apt-get install -y cloudflare-warp

# Register Cloudflare Warp (this may require manual setup or script modification)
RUN warp-cli registration new
RUN warp-cli set-mode proxy

COPY . /

RUN /etc/periodic/weekly/update_mmdb.sh

# Install shadowbox.
WORKDIR /opt/outline-server

CMD warp-cli connect && /cmd.sh
#CMD ["/cmd.sh"]
