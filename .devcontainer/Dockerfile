FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

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
    libc6-dev \
    gdb \
    clang-format \
    clang-tidy \
    file \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /workspaces/password-hash-cracker

# Install GEF for debugging
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

ENV CMAKE_C_COMPILER=/usr/bin/gcc CMAKE_CXX_COMPILER=/usr/bin/g++
