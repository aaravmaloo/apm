# Contributing to APM

Thanks for contributing. APM is a security-sensitive CLI, so we prioritize small, well-tested changes.

## Build
APM is now a hybrid Go + Rust project. The supported build path is the repo scripts in [`scripts/`](scripts), which compile the native Rust library and then link the Go CLI against it.

```bash
# Hybrid CLI build
./scripts/build.sh

# Test Go modules plus Rust crates
./scripts/test.sh
```

On Windows, use [`scripts/build.ps1`](scripts/build.ps1) and [`scripts/test.ps1`](scripts/test.ps1).

## AI-Generated Code
While contributing to APM, I would strongly advise writing code by yourself and using AI to refactor it. However, AI written code is also NOT discouraged, but it will take longer than usual to review the AI generated code.
