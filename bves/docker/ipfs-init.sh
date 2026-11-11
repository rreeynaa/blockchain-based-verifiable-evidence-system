#!/bin/sh
# Runs inside the Kubo container before the daemon starts.
# Bind the RPC API on all interfaces *inside* the container; docker-compose publishes
# it on 127.0.0.1 only. Never expose port 5001 publicly: it is an unauthenticated admin API.
ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001
ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080
