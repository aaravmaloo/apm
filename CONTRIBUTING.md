# Contributing to APM

Thanks for contributing. APM is a security-sensitive CLI, so we prioritize small, well-tested changes.

## Build
There is a faceid tag, for people contributing to ```faceid``` feature. It takes quite a while to setup, since it requires OpenCV and GoCV; and would certainly be a time-waster for people contributing to not faceid realted features.

```bash
# Standard build
go build -o pm.exe

# Face ID build (requires native OpenCV + dlib)
go build -tags faceid -o pm.exe
```

Face ID is behind a build tag because it depends on native OpenCV/dlib libraries that are not required for the core CLI.

## AI-Generated Code
While contributing to APM, I would strongly advise writing code by yourself and using AI to refactor it. However, AI written code is also NOT discouraged, but it will take longer than usual to review the AI generated code.