# Stage 0: jimple2json — converts Soot's textual Jimple into the JSON that ESBMC's Jimple
# frontend reads (ESBMC rejects textual Jimple with "json.exception.parse_error ... 'p'").
# Upstream builds against aeson 1.x; with aeson >= 2 one signature needs a Key instead of Text.
FROM haskell:9.4 AS jimple2json
# optionally pin a commit/tag with --build-arg JIMPLE2JSON_REF=<ref>; default is the default branch
ARG JIMPLE2JSON_REF=
RUN git clone https://github.com/rafaelsamenezes/jimple2json /src && cd /src && if [ -n "${JIMPLE2JSON_REF}" ]; then git checkout "${JIMPLE2JSON_REF}"; fi
WORKDIR /src
# the patch must precede any build: cabal builds the library even for --only-dependencies
RUN sed -i 's/maybeToPair :: ToJSON a => Maybe a -> T.Text -> \[Pair\]/maybeToPair :: ToJSON a => Maybe a -> Key -> [Pair]/' src/ToJson.hs
RUN cabal update && cabal build exe:jimple-exe -j && cp "$(cabal list-bin exe:jimple-exe)" /jimple2json && strip /jimple2json

# Stage 1: Build Environment Setup
FROM ubuntu:24.04 AS builder

# Set environment variables to ensure non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

# Define arguments for ESBMC version and download URL.
# From v8.4 the release asset is a single 'esbmc-linux.zip'; earlier tags used
# 'release-ubuntu-24.04--b.RelWithDebInfo.-e.OFF.zip'.  Both unpack to bin/esbmc,
# so only the URL differs when pinning an older version.
ARG ESBMC_VERSION=v8.4
ARG ESBMC_URL=https://github.com/esbmc/esbmc/releases/download/${ESBMC_VERSION}/esbmc-linux.zip
# sha256 of the v8.4 esbmc-linux.zip; pass an empty value to skip the check for another version
ARG ESBMC_SHA256=68bb71128e0c3c2db090955e7a302533a8a11a9d898df7f169c22311a0ec5078
ARG ESBMC_INSTALL_DIR=/opt/esbmc

# Solidity compiler version (static Linux binary)
ARG SOLC_VERSION=0.8.26

# Soot version for Kotlin/Jimple IR generation
# 4.3.0 (not newer): from 4.4 Soot quotes type names ('void') and ESBMC cannot resolve them
ARG SOOT_VERSION=4.3.0

# Install essential dependencies and development tools
# Note: 'kotlin' is intentionally excluded from apt — Ubuntu 24.04 ships Kotlin 1.3.x
# which is missing String.lowercase(), uppercase(), ArrayDeque and many other 1.5+ APIs.
# We install a current release from the official GitHub releases below instead.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    unzip \
    ca-certificates \
    build-essential \
    g++ \
    openjdk-17-jdk \
    python3 \
    python3-pip \
    python3-dev \
    libgmp10 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Kotlin 1.9.24 from official JetBrains releases.
# The Ubuntu apt 'kotlin' package is 1.3.x and lacks modern stdlib APIs.
ARG KOTLIN_VERSION=1.9.24
RUN wget -q -O /tmp/kotlin-compiler.zip \
    "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip" && \
    unzip /tmp/kotlin-compiler.zip -d /opt/ && \
    rm /tmp/kotlin-compiler.zip

ENV PATH="/opt/kotlinc/bin:${PATH}"

# Download and unpack ESBMC
RUN echo "Downloading ESBMC from ${ESBMC_URL}" && \
    mkdir -p ${ESBMC_INSTALL_DIR} && \
    wget -q -O /tmp/esbmc.zip ${ESBMC_URL} && \
    { [ -z "${ESBMC_SHA256}" ] || echo "${ESBMC_SHA256}  /tmp/esbmc.zip" | sha256sum -c -; } && \
    unzip /tmp/esbmc.zip -d ${ESBMC_INSTALL_DIR} && \
    echo "ESBMC extracted to ${ESBMC_INSTALL_DIR}" && \
    rm /tmp/esbmc.zip

# Add ESBMC binary directory to the system PATH
ENV PATH="${ESBMC_INSTALL_DIR}/bin:${PATH}"

# Install Python packages required by the ESBMC Python frontend:
#   ast2json  — converts Python AST to JSON for ESBMC's parser
#   mypy      — ESBMC Python frontend invokes mypy for type inference
RUN pip3 install --no-cache-dir --break-system-packages ast2json mypy

# Download solc static binary — required by the ESBMC Solidity frontend to generate AST
RUN wget -q -O /usr/local/bin/solc \
    "https://github.com/ethereum/solidity/releases/download/v${SOLC_VERSION}/solc-static-linux" && \
    chmod +x /usr/local/bin/solc

# Download Soot uber-jar — used to convert compiled Kotlin bytecode to Jimple IR for ESBMC
# Note: ESBMC's Jimple frontend reads a JSON form of Jimple, so Soot's output is passed through jimple2json
RUN wget -q -O /opt/soot.jar \
    "https://repo1.maven.org/maven2/org/soot-oss/soot/${SOOT_VERSION}/soot-${SOOT_VERSION}-jar-with-dependencies.jar"

COPY --from=jimple2json /jimple2json /usr/local/bin/jimple2json

# Set a default working directory for the container
WORKDIR /work

# Default command: Show ESBMC version to verify installation upon container start
CMD ["esbmc", "--version"]
