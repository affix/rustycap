# RustyCap

RustyCap is a network packet sniffer written in Rust that specializes in capturing and parsing network packets to search for credentials transmitted over unsecured connections. Designed with performance and safety in mind, it leverages Rust's powerful type system and zero-cost abstractions to efficiently process traffic on the wire.

## Features

- **Live Packet Capture**: Monitors network traffic in real-time, capturing data as it traverses the network.
- **Credential Parsing**: Scans for patterns in packet payloads that resemble authentication information such as usernames and passwords.
- **Protocol Analysis**: Understands common protocols (HTTP, FTP, etc.) to effectively extract potential credentials.
- **Safe and Efficient**: Written in Rust, RustyCap is memory safe and free from common bugs found in similar tools written in languages without strict ownership models.
- **Extensible**: Designed to be easily extended to support new protocols and credential formats.

## Installation

To install RustyCap, ensure you have the latest stable version of Rust installed on your machine. RustyCap can be installed directly using `cargo`, Rust's package manager and build system.

```bash
git clone https://github.com/affix/rustycap.git
cd rustycap
cargo build --release
```

The executable will be located in the ./target/release directory after the build completes.

Usage
To start capturing packets with RustyCap, run the following command:

```bash
sudo rustycap <device_name>
```
Replace eth0 with the network interface you wish to monitor.

Note: RustyCap requires root privileges to capture packets from a network interface.

Contributions
Contributions to RustyCap are welcome! Please submit a pull request or open an issue if you have ideas for improvement or have found a bug.

License
RustyCap is open-source software licensed under the MIT License. See the LICENSE file for more details.

Disclaimer
RustyCap is intended for security research and should not be used on any network without explicit permission. The authors of RustyCap are not responsible for misuse or for any damage that you may cause.

Copyright (c) 2023 Keiran Smith