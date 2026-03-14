# Contributing

Thanks for contributing to APM. This page covers the fastest path to a clean build and a smooth review.

## Build

```bash
# Standard build
go build -o pm.exe

# Face ID build (requires native OpenCV + dlib)
go build -tags faceid -o pm.exe
```

Face ID is behind a build tag because it depends on native OpenCV/dlib libraries that are not required for the core CLI.

## Pull Requests

- Keep changes focused and scoped.
- Include a short description of what changed and why.
- Mention any manual test steps you ran.

## AI-Generated Code

AI-generated changes take longer to review. If possible, write the code yourself and use AI only as a collaborator or reviewer while building APM.
