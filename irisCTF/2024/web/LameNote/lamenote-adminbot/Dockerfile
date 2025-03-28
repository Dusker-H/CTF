# Base image
FROM gcr.io/kctf-docker/challenge@sha256:0f7d757bcda470c3bbc063606335b915e03795d72ba1d8fdb6f0f9ff3757364f

RUN apt-get update && apt-get install -y gnupg2 wget socat

# Install dependencies for Puppeteer
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
    && wget -q -O - https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yq --no-install-recommends \
        ca-certificates \
        fonts-liberation \
        libappindicator3-1 \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libc6 \
        libcairo2 \
        libcups2 \
        libdbus-1-3 \
        libexpat1 \
        libfontconfig1 \
        libgbm1 \
        libgcc1 \
        libglib2.0-0 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libstdc++6 \
        libx11-6 \
        libx11-xcb1 \
        libxcb1 \
        libxcomposite1 \
        libxcursor1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxi6 \
        libxrandr2 \
        libxrender1 \
        libxshmfence1 \
        libxss1 \
        libxtst6 \
        lsb-release \
        wget \
        xdg-utils \
        nodejs \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV DOMAIN="localhost"
ENV BLOCK_SUBORIGINS="0"
ENV REGISTERED_DOMAIN="localhost"
ENV PUPPETEER_CACHE_DIR="/home/user/.cache/puppeteer"
ENV BOT_TIMEOUT="1000"

# Prepare bot environment
RUN mkdir /home/user && cd /home/user && npm install puppeteer
COPY bot.js /home/user/

# CMD to start the bot and socat
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"kctf_pow socat STDIN TCP:localhost:1338" & \
    node /home/user/bot.js
