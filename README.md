# Hybrid Post-Quantum Signature Upload System

This repository contains a hybrid (classical + post-quantum) digital signature system designed for secure image transmission from an embedded device (Raspberry Pi) to a server running inside WSL (Windows Subsystem for Linux).

The system implements:
- Hybrid digital signatures (OpenSSL + liboqs)
- A custom TCP/HTTP-style upload protocol
- A WSL-hosted server exposed to the local network via Windows port forwarding
- End-to-end verification and tamper detection

This setup is intended for **lab, coursework, and controlled network environments**.

---

## Architecture Overview

```
Embedded Device (Raspberry Pi)
        |
        |  TCP (port 8000)
        v
Windows Host IP (LAN)
        |
        |  netsh portproxy
        v
WSL (Linux)
  └── server (listening on 0.0.0.0:8000)
```

---

## Prerequisites

### Common
- Linux (WSL and Raspberry Pi)
- CMake ≥ 3.20
- Ninja
- GCC / Clang
- Git

### Crypto Dependencies
- OpenSSL (development headers)
- liboqs (Open Quantum Safe)

---

## Part 1 — WSL Setup (Server Machine)

### Install dependencies

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    pkg-config \
    ninja-build \
    libssl-dev \
    libcurl4-openssl-dev \
    git
```

---

### Build and install liboqs

```bash
mkdir -p ~/ps-sign
cd ~/ps-sign

git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cd liboqs

rm -rf build
cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON

cmake --build build
sudo cmake --install build
sudo ldconfig
```

---

### Build the project (WSL)

```bash
cd ~/ps-sign/project
rm -rf build

cmake -S . -B build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=/usr/local

cmake --build build -j
```

---

### Run the server (WSL)

```bash
cd build
./server
```

Verify:

```bash
ss -tlnp | grep :8000
```

---

## Part 2 — Windows Port Forwarding

Run in **Administrator PowerShell**:

```powershell
netsh interface portproxy add v4tov4 `
  listenaddress=0.0.0.0 listenport=8000 `
  connectaddress=<WSL_IP> connectport=8000

netsh advfirewall firewall add rule name="WSL APP 8000" `
  dir=in action=allow protocol=TCP localport=8000
```

---

## Part 3 — Raspberry Pi (Embedded System)

### Install dependencies

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    pkg-config \
    ninja-build \
    libssl-dev \
    libcurl4-openssl-dev \
    git
```

---

### Transfer project

```bash
rsync -av --delete -e ssh \
    <PROJECT_PATH> admin@<PI_IP>:/home/admin/ps-sign/project/
```

---

### Build liboqs

```bash
cd ~/ps-sign/liboqs
rm -rf build

cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON

cmake --build build
sudo cmake --install build
sudo ldconfig
```

---

### Build project

```bash
cd ~/ps-sign/project
rm -rf build

cmake -S . -B build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=/usr/local

cmake --build build -j
```

---

### Configure endpoint

Edit `config.h`:

```c
#define SERVER_IP   "<WINDOWS_IP>"
#define SERVER_PORT 8000
```

---

## Usage

```bash
cd build
./server        # WSL only
./hybrid_app    # Embedded system
./verify        # Verifies the signature
./extract_image # Extracts the image to a .png  
./file_tamper   # Modifies the signed .bin file resulting in a false verification
```

---

## Notes

- The embedded system must always connect to the **Windows host IP**
- Port forwarding must be rechecked if the network changes
- This setup is not intended for public or production deployment
