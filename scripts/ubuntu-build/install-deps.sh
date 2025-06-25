#!/bin/bash

packages=(
  libbenchmark-dev
  libcgroup-dev
  libcrypto++-dev
  libgmock-dev
  libgtest-dev
  libhugetlbfs-dev
  libssl-dev
  libtbb-dev
  liburing-dev
)

apt install -y "${packages[@]}"
