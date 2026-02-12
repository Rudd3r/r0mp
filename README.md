# #R0MP:> 

R0mp is a tool for spinning up temporary VMs using QEMU and Docker images. Pull any Docker image and run it as a 
lightweight QEMU VM with SSH access, port forwarding, and volume mounting.

## Features

- **Docker Images as VMs**: Convert Docker images to bootable QEMU VMs
- **SSH Access**: Automatic SSH key generation and access
- **Port Forwarding**: Expose VM ports to host (`-p host:guest`)
- **Volume Mounting**: Mount host directories (`-v host:guest`)
- **Resource Control**: Configure CPU and memory (`-c`, `-m`)
- **Network Proxy**: Built-in proxy with policy controls
- **Ephemeral**: Rafts are temporary by design

## Build

```bash
git clone https://github.com/Rudd3r/r0mp
cd r0mp
make r0mp
```

## Requirements

- QEMU

## Quick Start

```bash
# Run a raft from an Alpine image
r0mp run -i alpine:latest

# Run with a custom name
r0mp run -n myraft -i ubuntu:22.04

# Run with port forwarding and volume mounting
r0mp run -i nginx:latest -p 8080:80 -v ./data:/data

# List running rafts
r0mp ls

# SSH into a raft
r0mp exec -it myraft /bin/sh

# Copy files to/from a raft
r0mp cp ./local-file myraft:/remote/path
r0mp cp myraft:/remote/file ./local-path

# Stop and remove a raft
r0mp stop myraft
r0mp rm myraft
```

## Commands

| Command  | Description                          |
|----------|--------------------------------------|
| `run`    | Create and start a new raft          |
| `start`  | Start an existing raft               |
| `stop`   | Stop a running raft (SIGTERM)        |
| `kill`   | Force kill a raft (SIGKILL)          |
| `rm`     | Remove a stopped raft                |
| `ls`     | List all rafts                       |
| `get`    | Get detailed raft information (JSON) |
| `exec`   | SSH into a running raft              |
| `cp`     | Copy files between host and raft     |
| `images` | List cached Docker images            |
| `rmi`    | Remove cached images                 |
| `policy` | Manage network policies              |

