FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    libcrypt-dev \
    libcriterion-dev \
    git \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Copy source code
COPY . .

# Fix the CMake error by adding minimum required version
RUN echo 'cmake_minimum_required(VERSION 3.10)' > /tmp/cmake_fix && \
    cat CMakeLists.txt >> /tmp/cmake_fix && \
    mv /tmp/cmake_fix CMakeLists.txt

# Build the project
RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make

# Add build directory to PATH
ENV PATH="/app/build:${PATH}"

# Set entrypoint script
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
