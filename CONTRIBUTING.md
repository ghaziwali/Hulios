# Contributing to Hulios

Thank you for your interest in contributing to Hulios. As a low-level network security utility, maintaining high standards of code correctness, sandbox security, and zero-leak network configuration is critical.

---

## 🛠️ Development Environment Setup

Hulios is composed of userspace Rust components and kernel-space eBPF programs. Building the eBPF programs requires specific system libraries and a Rust nightly compiler.

### 1. System Prerequisites
Ensure your development machine has LLVM, clang, and the libelf headers installed.

*   **Arch Linux:**
    ```bash
    sudo pacman -S clang libelf
    ```
*   **Debian/Ubuntu:**
    ```bash
    sudo apt-get install -y clang libelf-dev
    ```

### 2. Rust Toolchain Configuration
The project is configured to automatically inherit the correct nightly compiler channel, components (`rust-src`), and targets (`bpfel-unknown-none`, `x86_64-unknown-linux-gnu`) through the root `rust-toolchain.toml` file.

When you run any `cargo` commands in this directory, `rustup` will automatically configure the correct environment. The only manual tool you need to install is the `bpf-linker`:

```bash
# Install the bpf-linker tool required for compilation
cargo install bpf-linker
```

---

## 📁 Workspace Structure

Hulios uses a multi-crate Cargo workspace to separate security privileges and capabilities:
*   [hulios/](file:///home/ghazi/script/hulios/hulios): The supervisor process wrapper (holds root privileges, spins up the worker, manages signals).
*   [hulios-ebpf/](file:///home/ghazi/script/hulios/hulios-ebpf): The kernel-space eBPF logic (handles socket marking and DNS redirection).
*   [hulios-cli/](file:///home/ghazi/script/hulios/hulios-cli): Command-line argument parsing and configuration merge.
*   [hulios-state/](file:///home/ghazi/script/hulios/hulios-state): The state-machine for startup operations, teardowns, and system recoveries.
*   [hulios-onionmasq/](file:///home/ghazi/script/hulios/hulios-onionmasq): Userspace Tor tunnel integration (wrapping the `onionmasq` runtime).
*   [hulios-dns/](file:///home/ghazi/script/hulios/hulios-dns): Custom Hickory DNS server implementation.
*   [hulios-netcompat/](file:///home/ghazi/script/hulios/hulios-netcompat): Handlers for Avahi-daemon suppression and system clock management.
*   [hulios-tun/](file:///home/ghazi/script/hulios/hulios-tun): TUN virtual interface creation and configuration.
*   [hulios-common/](file:///home/ghazi/script/hulios/hulios-common): Shared structures and constants used by both userspace and eBPF.

---

## 🧪 Local Verification & Tests

Before submitting a Pull Request, you must verify your changes pass all local compilation, lint, and runtime checks.

### 1. Compile Code
```bash
cargo build --release
```
*Note: This automatically triggers compilation of `hulios-ebpf` bytecode and includes it directly inside the final `hulios` binary.*

### 2. Run Tests
```bash
cargo test --workspace
```
*Note: Some integration tests modify network routing configurations or namespaces and may require root privileges (`sudo cargo test`).*

### 3. Check Lints and Format
We enforce strict style checks to keep the codebase clean:
```bash
# Run Clippy (warnings are treated as errors)
cargo clippy --workspace --all-targets -- -D warnings

# Check Code Formatting
cargo fmt --all -- --check
```

---

## 📬 Pull Request Guidelines

Hulios follows the **GitHub Flow** branching model. Always create your feature branches off the latest `main` branch, and target the `main` branch when opening a Pull Request.

When submitting a Pull Request:
1.  **Leak Verification:** Any change to the state machine or routing tables must be validated for leaks. Run `sudo hulios diagnose` or monitor the interface with `tcpdump` before opening the PR.
2.  **PR Template:** Fill out the pull request template completely. You must include your testing environment details:
    *   Operating System/Distribution
    *   Kernel Version (`uname -r`)
    *   Systemd & NetworkManager active states
3.  **Warnings & Lints:** Ensure the code compiles warning-free on the nightly compiler.
