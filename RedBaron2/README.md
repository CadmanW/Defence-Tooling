# rb2

Red Baron 2 is our sucessor to the original Red Baron EDR. 

## Features / Intended Use 

- Binary-based firewall for layer-7 permissioning
  - Netfilter-queue enforcement inspired by opensnitch
  - Kill-based enforcement inspired by tetragon
- Yara-x scanning
  - In-memory yara scanning
  - Pre-exec yara scanning
- Process exec logging
  - Alert rule engine
  - Weighted process baselining
- PAM auth logging
- Encrypted TTY session tracking similar to Elastic EDR (uses a modified form of their GPL2 eBPF code)
- File integrity monitoring for modifications
- HTTP(S)/DNS request logging inspired by bcc
- Log forwarding to multiple places
- s3 object storage forwarding for encrypted tty sessions

A minimal FreeBSD build features:

- Yara-x memory scanning
- Process exec logging with the same rule engine
- Auth logging
- Audit event logging
- Binary-based layer-7 firewall
- Log forwarding
- Audit event forwarding
  - Process events
  - Network events
  - Login events
  - Kill processes based on network events

This repository also contains a go-based web-ui for viewing tty sessions on an s3 bucket as well as a small program to decrypt the s3 sessions into a asciinema-compatible viewing format.

## Benefit
- rb2 solves a lot of problems that current open source Linux tooling does not provide
- rb2 is primarily focused on security observability
- rb2 introduces a firewall that is developer/end user friendly
- rb2 is widely comptaibile with older systems and falls back to auditd when eBPF is not available

## Footprint

- rb2 is the lighest and least intrusive AV/EDR that we can bring into a CCDC environment.
- Memory footprint with a complete featureset stays around 50MB.
- Total compiled musl binary sits around 30MB.
- All imported third party rust libraries were chosen with care and measured against overall musl build sizes

## Reliability and Testing Methodology / Potential Risks

- The code base above has formatting and logic standards 
- The releases get tested in an end to end testing workflow on several AWS AMIs for each unique featureset red baron provides
- Most of red baron, outside of detected malware via yara and the firewall, is designed with a "fail open" and complain about strategy to prevent outages
- This project has been tested in close to 7 unique cybersecurity competitions
- Most high level functions support tracing for development and debugging
- AI note: while AI has been used in this project, great care has been established to review code by hand in our PRs.
- Design descision such as avoiding using a custom kernel module and using eBPF / fanotify diminish potential risks
- Most all options are togglable in a configuration file
- If one part of Red Baron fails, the rest of the project will keep working
- By default, install will not enable rb2 so that a reboot of the system will not start red baron automatically in case of failure

## Tar file note
- Because of offline building requirments, tar files are present in this repo
- All tar files can be decompressed with no password
- All tar files do not contain binaries
- All tar files have been generated via an GitHub Action workflow, found in the .github/workflows folder in the repo.
- Tar file inventory as follows: libbpf.tar.xz (git submodule containing libbpf code), yara_linux.tar.xz (yara rules mostly derived from Elastic's rules), and vendor.tar.xz (created via vendor workflow, cargo vendor).

## Nix Build and Development

This project includes a Nix flake for reproducible builds and development environments.

If you don't have nix download from [Here](https://docs.determinate.systems/determinate-nix/)

### Using Nix Build

To build the project using Nix:

```shell
nix build
```

This will build the project and create a `result` symlink pointing to the build output.

Other useful commands include:

```shell
nix develop
nix build .#clippy
nix build .#test
nix build .#fmt
nix build .#freebsd
```

### Using Nix Development Environment

To enter a development shell with all required dependencies:

```shell
nix develop
```

This will provide you with:

- Rust toolchains (stable and nightly)
- LLVM tools
- Cross-compilation toolchains
- All other build dependencies

Once in the development shell, you can use standard Cargo commands like `cargo build`, `cargo test`, etc.

## Prerequisites

for non-nix builds:

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. LLVM: (e.g.) `brew install llvm` (on macOS)
1. C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo build --release
```

The default target is `x86_64-unknown-linux-musl` for portability.

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

To build decypt cast:

```shell
cargo build -p decypt-cast --release
```

## Credits

- https://github.com/elastic/ebpf
- https://github.com/SigmaHQ/sigma
- https://github.com/endgameinc/RTA
- https://github.com/redcanaryco/atomic-red-team
- https://github.com/evilsocket/opensnitch
- https://github.com/asciinema/asciinema
- https://github.com/kubearmor/KubeArmor
- https://www.kernel.org/
- https://github.com/elastic/protections-artifacts

## License

With the exceptions below, the maintainers reserve the rights to rb2.

### eBPF

All eBPF code in rb2-ebpf is distributed under either the terms of the
[GNU General Public License, Version 2]

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

### RTA rules

The [Red Team Automation (RTA)](https://github.com/endgameinc/RTA) scripts are licensed under the GPL3.
These were used to generate the flying ace rules in flying-ace-engine/rules/rta.
[GNU General Public License, Version 3]

### Elastic rules

The rules from [Elastic's Protection Artifacts](https://github.com/elastic/protections-artifacts) are licensed under their own license.

This restricts our ability to sell or provide these rulesets as a service.
The elastic yara rules and flying-ace rules present at flying-ace-engine/rules/elastic bundled with this project are licensed under their license.
[Elastic License 2.0]

[elastic license 2.0]: https://www.elastic.co/licensing/elastic-license
[gnu general public license, version 2]: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html#SEC1
[gnu general public license, version 3]: https://www.gnu.org/licenses/gpl-3.0.html#license-text
