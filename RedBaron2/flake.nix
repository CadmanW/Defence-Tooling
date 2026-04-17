{
  description = "Red Baron 2: A Crane-based Nix build for the rb2 binary";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane.url = "github:ipetkov/crane";
    yara-rules = {
      url = "https://github.com/nmagill123/compiled-yara-rules-rb2/releases/download/v20260406-022656/linux.tar.xz";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
      yara-rules,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        lib = pkgs.lib;

        # Determine target architecture and package set
        isAarch64 = system == "aarch64-linux";
        
        muslPkgs = if isAarch64 
          then pkgs.pkgsCross.aarch64-multiplatform-musl 
          else pkgs.pkgsCross.musl64;

        rustTarget = if isAarch64 
          then "aarch64-unknown-linux-musl" 
          else "x86_64-unknown-linux-musl";

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          targets = [ rustTarget "x86_64-unknown-freebsd" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = lib.cleanSourceWith {
          src = craneLib.path ./.;
          filter = path: type:
            (craneLib.filterCargoSources path type) ||
            # eBPF C source, headers, and Makefiles
            (lib.hasInfix "/rb2-ebpf/" path) ||
            # RHAI/detection rules embedded at build time
            (lib.hasInfix "/flying-ace-engine/rules/" path);
        };

        # Common dev tooling (host)
        commonBuildInputs = with pkgs; [
          clang
          llvm
          stdenv.cc
        ];

        # Inputs for musl cross builds (target-side libs come from muslPkgs)
        muslBuildInputs =
          commonBuildInputs
          ++ (with muslPkgs; [
            libbpf
          ]);

        # Stage the vendored libbpf layout expected by rb2-ebpf/Makefile.
        libbpfSetup = pkgsSet: ''
          mkdir -p rb2-ebpf/libbpf/src rb2-ebpf/build/libbpf/bpf
          cp ${pkgsSet.libbpf}/lib/libbpf.a rb2-ebpf/libbpf/src/
          cp ${pkgsSet.libbpf}/include/bpf/bpf_core_read.h rb2-ebpf/build/libbpf/bpf/
          cp ${pkgsSet.libbpf}/include/bpf/bpf_endian.h rb2-ebpf/build/libbpf/bpf/
          cp ${pkgsSet.libbpf}/include/bpf/bpf_helper_defs.h rb2-ebpf/build/libbpf/bpf/
          cp ${pkgsSet.libbpf}/include/bpf/bpf_helpers.h rb2-ebpf/build/libbpf/bpf/
          cp ${pkgsSet.libbpf}/include/bpf/bpf_tracing.h rb2-ebpf/build/libbpf/bpf/
        '';

        # Helper to copy YARA rules to yara_linux directory
        # Note: yara-rules is already extracted by Nix since it's a tarball input
        yaraRulesSetup = ''
          if [ ! -d yara_linux ]; then
            echo "Copying YARA rules from ${yara-rules} to yara_linux/"
            cp -r ${yara-rules} yara_linux
            chmod -R u+w yara_linux
          fi
        '';

        # FreeBSD 13.x system libraries not in Zig's bundled sysroot.
        # Fetched from the official FreeBSD base release so crates like sysinfo
        # can link against libkvm, libprocstat, libmemstat, and libdevstat.
        # To update the hash: nix-prefetch-url <url>
        freebsdSyslibs = pkgs.runCommand "freebsd-syslibs" {
          src = pkgs.fetchurl {
            url = "https://download.freebsd.org/ftp/releases/amd64/amd64/14.4-RELEASE/base.txz";
            hash = "sha256-dp9gpu6ik4rWt5Q8+8wX3699H3ulmjK4aaADSTAt+FM=";
          };
          nativeBuildInputs = [ pkgs.gnutar pkgs.xz ];
        } ''
          mkdir -p $out/lib $out/include
          # FreeBSD 14.x layout: versioned .so files are split between ./lib/ and
          # ./usr/lib/; unversioned symlinks are in ./usr/lib/.
          tar -xJf $src -C $TMPDIR \
            './lib/libkvm.so.7' \
            './lib/libdevstat.so.7' \
            './lib/libgeom.so.5' \
            './usr/lib/libprocstat.so.1' \
            './usr/lib/libmemstat.so.3' \
            './usr/include/kvm.h' \
            './usr/include/memstat.h' \
            './usr/include/devstat.h' \
            './usr/include/libprocstat.h' \
            './usr/include/libgeom.h' 2>/dev/null || true
          cp -f $TMPDIR/lib/lib*.so.*     $out/lib/ 2>/dev/null || true
          cp -f $TMPDIR/usr/lib/lib*.so.* $out/lib/ 2>/dev/null || true
          # Create unversioned symlinks (libkvm.so -> libkvm.so.7 etc.)
          for f in $out/lib/lib*.so.*; do
            [ -f "$f" ] || continue
            base="''${f%.[0-9]*}"
            [ -e "$base" ] || ln -s "$(basename "$f")" "$base"
          done
          cp -f $TMPDIR/usr/include/kvm.h          $out/include/ 2>/dev/null || true
          cp -f $TMPDIR/usr/include/memstat.h       $out/include/ 2>/dev/null || true
          cp -f $TMPDIR/usr/include/devstat.h       $out/include/ 2>/dev/null || true
          cp -f $TMPDIR/usr/include/libprocstat.h   $out/include/ 2>/dev/null || true
          cp -f $TMPDIR/usr/include/libgeom.h       $out/include/ 2>/dev/null || true
        '';

        # FreeBSD cross-compilation env (uses zig as C compiler)
        freebsdCrossEnv = {
          CARGO_BUILD_TARGET = "x86_64-unknown-freebsd";
          CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER = "${freebsdCc}";
          # Let rustc find the FreeBSD system libraries when resolving link-lib directives
          CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_RUSTFLAGS = "-L ${freebsdSyslibs}/lib";
          CC_x86_64_unknown_freebsd = "${freebsdCc}";
          CXX_x86_64_unknown_freebsd = "${freebsdCxx}";
        };

        # Env blocks
        baseEnv = {
          NIX_HARDENING_ENABLE = "";
          RUST_BACKTRACE = "1";
        };

        nativeCEnv = pkgsSet: {
          PKG_CONFIG_PATH = "${pkgsSet.elfutils.dev}/lib/pkgconfig:${pkgsSet.zlib.dev}/lib/pkgconfig:${pkgsSet.libbpf}/lib/pkgconfig";
          CFLAGS = "-I${pkgsSet.elfutils.dev}/include -I${pkgsSet.zlib.dev}/include -I${pkgsSet.libbpf}/include";
          LDFLAGS = "-L${pkgsSet.elfutils}/lib -L${pkgsSet.zlib}/lib -L${pkgsSet.libbpf}/lib";
          C_INCLUDE_PATH = "${pkgsSet.elfutils.dev}/include:${pkgsSet.zlib.dev}/include:${pkgsSet.libbpf}/include";
          LIBRARY_PATH = "${pkgsSet.elfutils}/lib:${pkgsSet.zlib}/lib:${pkgsSet.libbpf}/lib";
        };

        muslCrossEnv = 
          let
            cc = "${muslPkgs.stdenv.cc}/bin/${rustTarget}-gcc";
            cxx = "${muslPkgs.stdenv.cc}/bin/${rustTarget}-g++";
            ar = "${muslPkgs.stdenv.cc}/bin/${rustTarget}-ar";
            linkerEnv = if isAarch64 then {
              CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = cc;
              CC_aarch64_unknown_linux_musl = cc;
              CXX_aarch64_unknown_linux_musl = cxx;
              AR_aarch64_unknown_linux_musl = ar;
              CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C target-feature=+crt-static -C link-arg=-lm";
            } else {
              CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = cc;
              CC_x86_64_unknown_linux_musl = cc;
              CXX_x86_64_unknown_linux_musl = cxx;
              AR_x86_64_unknown_linux_musl = ar;
              CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C target-feature=+crt-static -C link-arg=-lm";
            };
          in
          {
            CARGO_BUILD_TARGET = rustTarget;
          } // linkerEnv // (nativeCEnv muslPkgs);

        # Zig-based FreeBSD cross-compiler wrappers.
        # Passes freebsdSyslibs so Zig's linker can resolve libkvm etc.
        freebsdCc = pkgs.writeShellScript "freebsd-cc" ''
          export ZIG_GLOBAL_CACHE_DIR="''${ZIG_GLOBAL_CACHE_DIR:-''${TMPDIR:-/tmp}/zig-cache}"
          args=()
          for arg in "$@"; do
            case "$arg" in
              --target=*) ;; # drop cc-rs's rust-style triple; we set zig's target below
              *) args+=("$arg") ;;
            esac
          done
          exec ${pkgs.zig}/bin/zig cc -target x86_64-freebsd \
            -L${freebsdSyslibs}/lib \
            -I${freebsdSyslibs}/include \
            "''${args[@]}"
        '';
        freebsdCxx = pkgs.writeShellScript "freebsd-cxx" ''
          export ZIG_GLOBAL_CACHE_DIR="''${ZIG_GLOBAL_CACHE_DIR:-''${TMPDIR:-/tmp}/zig-cache}"
          args=()
          for arg in "$@"; do
            case "$arg" in
              --target=*) ;; # drop cc-rs's rust-style triple; we set zig's target below
              *) args+=("$arg") ;;
            esac
          done
          exec ${pkgs.zig}/bin/zig c++ -target x86_64-freebsd \
            -L${freebsdSyslibs}/lib \
            -I${freebsdSyslibs}/include \
            "''${args[@]}"
        '';

        # One helper to make all crane builds with minimal duplication
        mkCrane =
          {
            pname,
            version ? "0.1.0",
            inputs,
            env,
            pre ? "",
            cargoArtifacts ? null,
            kind ? "package", # "package" | "deps" | "clippy" | "test" | "fmt"
            extra ? { },
          }:
          let
            core = {
              inherit src pname version;
              nativeBuildInputs = inputs;
              preBuild = pre;
            }
            // env
            // baseEnv
            // extra;
          in
          if kind == "deps" then
            craneLib.buildDepsOnly core
          else if kind == "clippy" then
            craneLib.cargoClippy (
              core
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets -- --deny warnings";
              }
            )
          else if kind == "test" then
            craneLib.cargoTest (core // { inherit cargoArtifacts; })
          else if kind == "fmt" then
            craneLib.cargoFmt core
          else
            craneLib.buildPackage (
              core // lib.optionalAttrs (cargoArtifacts != null) { inherit cargoArtifacts; }
            );

        # Artifacts
        deps-musl = mkCrane {
          pname = "rb2-deps";
          inputs = muslBuildInputs;
          env = muslCrossEnv;
          kind = "deps";
          pre = ''
            ${libbpfSetup muslPkgs}
            ${yaraRulesSetup}
            export CRANE_BUILD_DEPS_ONLY=1
          '';
        };

        # FreeBSD artifacts
        deps-freebsd = mkCrane {
          pname = "rb2-deps-freebsd";
          inputs = commonBuildInputs ++ [ pkgs.zig ];
          env = freebsdCrossEnv;
          kind = "deps";
          pre = ''
            ${yaraRulesSetup}
            export CRANE_BUILD_DEPS_ONLY=1
          '';
          extra = {
            cargoExtraArgs = "-p rb2-freebsd";
          };
        };

        rb2-freebsd = mkCrane {
          pname = "rb2-freebsd";
          inputs = commonBuildInputs ++ [ pkgs.zig ];
          env = freebsdCrossEnv;
          cargoArtifacts = deps-freebsd;
          pre = yaraRulesSetup;
          extra = {
            doCheck = false;
            cargoExtraArgs = "-p rb2-freebsd";
            meta = with lib; {
              description = "Red Baron 2 binary cross-compiled for FreeBSD";
              license = licenses.mit;
            };
          };
        };

        rb2-freebsd-clippy = mkCrane {
          pname = "rb2-freebsd-clippy";
          inputs = commonBuildInputs ++ [ pkgs.zig ];
          env = freebsdCrossEnv;
          cargoArtifacts = deps-freebsd;
          pre = yaraRulesSetup;
          kind = "clippy";
          extra = {
            cargoExtraArgs = "-p rb2-freebsd";
          };
        };

        # Build targets
        rb2 = mkCrane {
          pname = "rb2";
          inputs = muslBuildInputs;
          env = muslCrossEnv;
          cargoArtifacts = deps-musl;
          pre = ''
            ${libbpfSetup muslPkgs}
            ${yaraRulesSetup}
          '';
          extra = {
            doCheck = false;
            meta = with lib; {
              description = "Red Baron 2 binary built with Crane, statically linked with musl";
              license = licenses.mit;
              maintainers = [ "yourname" ];
            };
          };
        };

        rb2-clippy = mkCrane {
          pname = "rb2-clippy";
          inputs = muslBuildInputs;
          env = muslCrossEnv;
          cargoArtifacts = deps-musl;
          pre = ''
            ${libbpfSetup muslPkgs}
            ${yaraRulesSetup}
          '';
          kind = "clippy";
        };

        rb2-test = mkCrane {
          pname = "rb2-test";
          inputs = muslBuildInputs;
          env = muslCrossEnv;
          cargoArtifacts = deps-musl;
          pre = ''
            ${libbpfSetup muslPkgs}
            ${yaraRulesSetup}
          '';
          kind = "test";
        };

        rb2-fmt = mkCrane {
          pname = "rb2-fmt";
          inputs = [ ];
          env = baseEnv;
          kind = "fmt";
        };

      in
      {
        packages = {
          default = rb2;
          red-baron = rb2;
          freebsd = rb2-freebsd;

          clippy = rb2-clippy;
          clippy-freebsd = rb2-freebsd-clippy;
          test = rb2-test;
          fmt = rb2-fmt;
        };

        checks = {
          inherit
            rb2
            rb2-clippy
            rb2-test
            rb2-fmt
            rb2-freebsd
            rb2-freebsd-clippy
            ;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = muslBuildInputs ++ [
            rustToolchain
            pkgs.cargo-bloat
            pkgs.cargo-edit
            pkgs.rust-analyzer

            pkgs.llvmPackages.bintools
            pkgs.llvmPackages.lld
            pkgs.zig
            pkgs.cargo-zigbuild
            pkgs.bpftools
            pkgs.linuxPackages.bpftrace
            pkgs.linuxPackages.bcc
          ];

          NIX_HARDENING_ENABLE = "";
          RUST_BACKTRACE = "1";

          # FreeBSD cross-compilation via zig (bundles FreeBSD sysroot)
          CC_x86_64_unknown_freebsd = "${freebsdCc}";
          CXX_x86_64_unknown_freebsd = "${freebsdCxx}";
          CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER = "${freebsdCc}";

          shellHook = ''
            # ensure libbpf is placed once per shell
            if [ ! -e rb2-ebpf/libbpf/src/libbpf.a ]; then
              ${libbpfSetup muslPkgs}
            fi
            # ensure yara rules are extracted once per shell
            if [ ! -d yara_linux ]; then
              ${yaraRulesSetup}
            fi
            
            # convenience exports for musl cross
            export CARGO_TARGET_${if isAarch64 then "AARCH64" else "X86_64"}_UNKNOWN_LINUX_MUSL_LINKER="${muslPkgs.stdenv.cc}/bin/${rustTarget}-gcc"
            export CC_${if isAarch64 then "aarch64" else "x86_64"}_unknown_linux_musl="${muslPkgs.stdenv.cc}/bin/${rustTarget}-gcc"
            export CXX_${if isAarch64 then "aarch64" else "x86_64"}_unknown_linux_musl="${muslPkgs.stdenv.cc}/bin/${rustTarget}-g++"
            export AR_${if isAarch64 then "aarch64" else "x86_64"}_unknown_linux_musl="${muslPkgs.stdenv.cc}/bin/${rustTarget}-ar"
            export CARGO_TARGET_${if isAarch64 then "AARCH64" else "X86_64"}_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-lm"

            echo "Development environment ready!"
            echo ""
            echo "Available commands:"
            echo "  For musl cross-compilation: cargo build --release"
            echo "  For production (statically linked): nix build"
            echo ""
            echo "Crane-specific commands:"
            echo "  Check code: nix build .#clippy"
            echo "  Run tests: nix build .#test"
            echo "  Check formatting: nix build .#fmt"
            echo ""
            echo "Output locations:"
            echo "  Musl binary: target/${rustTarget}/release/rb2"
            echo "  Production binary: result/bin/rb2"

          '';
        };
      }
    );
}
