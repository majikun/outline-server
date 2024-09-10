# Use Ubuntu-based Node.js image
FROM node:18.18.0

# Install necessary packages
RUN apt-get update && apt-get install -y \
    apt-transport-https curl gnupg lsb-release iproute2

# Add Cloudflare WARP repository and install the client
RUN curl https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list \
    && apt-get update && apt-get install -y cloudflare-warp

# Register WARP and set it to proxy mode
RUN warp-svc &
RUN warp-cli registration new
RUN warp-cli set-mode proxy

# Copy project files (Outline server)
COPY . /

# Update MMDB databases (Outline server)
RUN /etc/periodic/weekly/update_mmdb.sh

# Set working directory for Outline server
WORKDIR /opt/outline-server

# Ensure WARP connects on container startup and run the Outline server
CMD warp-cli connect && /cmd.sh
#CMD /cmd.sh