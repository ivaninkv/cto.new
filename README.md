# Port Scanner

A high-performance CLI port scanner written in Zig with support for parallel scanning, CIDR notation, and port ranges.

## Features

- ✅ Fast parallel port scanning with configurable worker threads
- ✅ CIDR notation support for scanning entire subnets (e.g., `192.168.1.0/24`)
- ✅ Port range support (e.g., `1-1024`)
- ✅ Host availability check before scanning
- ✅ 1-second connection timeout for fast scanning
- ✅ Clean and informative output

## Requirements

- Zig 0.15.2 or later

## Building

```bash
zig build
```

The compiled binary will be located at `zig-out/bin/port-scanner`.

## Usage

```
port-scanner [options]

Options:
  -s, --hosts <string>    Hosts to scan (comma-separated, supports CIDR notation)
                          Examples: scanme.nmap.org,example.com,192.168.1.0/24
                          Required

  -p, --ports <string>    Ports to scan (comma-separated, supports ranges)
                          Examples: 1-1024,6443,8443
                          Default: 22,80,443

  -w, --workers <int>     Number of worker threads for parallel scanning
                          Default: 100

  -h, --help              Show help message
```

## Examples

### Scan a single host with default ports (22, 80, 443)

```bash
./zig-out/bin/port-scanner -s example.com
```

### Scan specific ports

```bash
./zig-out/bin/port-scanner -s example.com -p 80,443,8080
```

### Scan a port range

```bash
./zig-out/bin/port-scanner -s scanme.nmap.org -p 1-1024
```

### Scan multiple hosts

```bash
./zig-out/bin/port-scanner -s example.com,google.com -p 80,443
```

### Scan a subnet using CIDR notation

```bash
./zig-out/bin/port-scanner -s 192.168.1.0/24 -p 22,80,443
```

### Adjust number of worker threads

```bash
./zig-out/bin/port-scanner -s 192.168.1.0/24 -p 1-1024 -w 200
```

## Output Format

The scanner outputs results in the following format:

```
Starting port scan...
Hosts: 2, Ports: 2, Workers: 50

=== Scan Results ===
example.com:80 - OPEN
example.com:443 - OPEN
google.com:80 - OPEN
google.com:443 - OPEN

Total scanned: 4, Open: 4, Closed: 0
```

Unreachable hosts are displayed separately:

```
nonexistent.host - HOST UNREACHABLE
```

## Architecture

The port scanner is built with the following components:

- **CLI Argument Parsing**: Handles all command-line options with validation
- **CIDR Expansion**: Expands CIDR notation into individual IP addresses
- **Port Range Parsing**: Supports both individual ports and ranges (e.g., `1-1024`)
- **Host Availability Check**: Pre-validates hosts before scanning
- **Job Queue**: Thread-safe queue for distributing scan jobs
- **Worker Threads**: Parallel workers for concurrent port scanning
- **Non-blocking Sockets**: Uses non-blocking sockets with poll() for timeout support

## Technical Details

- **Timeout**: Each connection attempt has a 1-second timeout using non-blocking sockets and poll()
- **Thread Safety**: Uses mutexes for thread-safe access to shared job and result queues
- **Performance**: Configurable worker count allows tuning for different scenarios
- **Memory Management**: Proper allocation and cleanup using Zig's allocator system

## License

This project is provided as-is for educational and practical use.
