# Face ID (Optional)

Face ID enables biometric unlock using local face recognition. It is **optional** and only available when APM is built with the `faceid` build tag because it depends on native OpenCV and dlib libraries.

## Build

```bash
# Standard build (no Face ID)
go build -o pm.exe

# Face ID build
go build -tags faceid -o pm.exe
```

## Commands

```bash
pm faceid enroll
pm faceid status
pm faceid test
pm faceid remove
```

## Storage

- **Models** are downloaded automatically to your user config directory under `apm/faceid/models`.
- **Enrollment** metadata is stored next to the vault at `faceid/enrollment.json`.

## Notes

- Face ID uses the default camera (index `0`).
- If Face ID fails, you can always unlock with your master password.
