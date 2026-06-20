# ============================================================
# SmartShield — Fixed Dockerfile for Factory Deployment
# ============================================================
# Changes from original:
#   - REMOVED: iris Go build stage (iris/ folder missing from repo)
#   - REMOVED: p2p4smartshield build step (folder missing from repo)
#   - Both are optional P2P trust modules, NOT needed for core IPS
#   - All other functionality (Zeek, Redis, Python, Kalipso) unchanged
# ============================================================

FROM ubuntu:22.04

# Avoid interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive

# Tell SmartShield it is running inside Docker
ENV IS_IN_A_DOCKER_CONTAINER=True

# SmartShield install directory inside the container
ENV smartshield_DIR=/smartshield

# Use bash for all RUN commands
SHELL ["/bin/bash", "-c"]

WORKDIR ${smartshield_DIR}

# Copy all project files into the container
COPY . $smartshield_DIR

# ── Step 1: Install system packages ──────────────────────────────────────────
RUN apt-get update -o Acquire::Retries=5 \
    && apt-get install -y --no-install-recommends --fix-broken --fix-missing \
        curl \
        gnupg \
        ca-certificates \
        python3 \
        python3-pip \
        python3-dev \
        wget \
        build-essential \
        file \
        lsof \
        net-tools \
        iproute2 \
        iptables \
        tshark \
        git \
        nodejs \
        npm \
        vim \
        less \
        unzip \
        nano \
        tmux \
        lsb-release \
        software-properties-common \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Step 2: Install Zeek 8 ───────────────────────────────────────────────────
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
        | tee /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
        | gpg --dearmor \
        | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends --fix-missing zeek-8.0 \
    && ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek \
    && ln -sf /opt/zeek/bin/zeek /usr/local/bin/bro \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Step 3: Compile Redis from source ────────────────────────────────────────
WORKDIR /
RUN pip3 install --no-cache-dir --upgrade pip \
    && curl -O https://download.redis.io/redis-stable.tar.gz \
    && tar xzf redis-stable.tar.gz \
    && cd redis-stable \
    && make distclean \
    && make MALLOC=libc \
    && rm -f /redis-stable.tar.gz

ENV PATH="$PATH:/redis-stable/src"

# ── Step 4: Install Python requirements ──────────────────────────────────────
WORKDIR ${smartshield_DIR}
RUN pip3 install --ignore-installed --no-cache-dir \
        -r install/requirements.txt \
    && chmod 774 smartshield.py

# ── Step 5: Install Kalipso (terminal UI node modules) ───────────────────────
RUN cd modules/kalipso \
    && npm install \
    && cd ${smartshield_DIR}

# ── Step 6: Git remote (needed by update_manager module) ─────────────────────
RUN git init \
    && git remote add origin \
        https://github.com/stratosphereips/StratosphereLinuxIPS.git

# ── Step 7: Create dummy iris placeholder ────────────────────────────────────
# The irisModule is an optional P2P trust component.
# We create an empty placeholder binary so no startup errors occur.
RUN mkdir -p modules/irisModule \
    && echo '#!/bin/bash' > modules/irisModule/iris \
    && echo 'echo "iris stub - P2P module not available"' >> modules/irisModule/iris \
    && chmod +x modules/irisModule/iris

WORKDIR ${smartshield_DIR}

CMD ["/bin/bash"]
