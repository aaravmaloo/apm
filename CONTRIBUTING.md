# Contributing to APM

Thanks for contributing. APM is a security-sensitive CLI, so we prioritize small, well-tested changes.

## Build
There is a faceid tag for people contributing to the ```faceid``` feature. It takes extra setup because it requires Rust, which is not needed for unrelated work.

```bash
# Standard build
go build -o pm.exe

# Face ID build (requires Rust)
./scripts/build.sh
```

Face ID is behind a build tag because it depends on the native Rust FaceID library, which is not required for the core CLI.

## AI-Generated Code
While contributing to APM, I would strongly advise writing code by yourself and using AI to refactor it. However, AI written code is also NOT discouraged, but it will take longer than usual to review the AI generated code.
