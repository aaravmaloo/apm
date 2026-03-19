# Face ID (Optional)

Face ID enables biometric unlock using local face recognition. It is **optional** and only available when APM is built with the `faceid` build tag because it depends on native OpenCV and dlib libraries.

It is a convenience layer over the normal unlock flow, not a replacement for the master password. If Face ID is unavailable or verification fails, you can still unlock with your password.

---

## Build

```bash
# Standard build (no Face ID)
go build -o pm.exe

# Face ID build
go build -tags faceid -o pm.exe
```

---

## Commands

```bash
pm faceid enroll
pm faceid status
pm faceid test
pm faceid remove
```

### `pm faceid enroll`

Registers a local face profile for future unlock attempts.

### `pm faceid status`

Shows whether Face ID enrollment metadata is present and available.

### `pm faceid test`

Runs a verification check without changing enrollment.

### `pm faceid remove`

Deletes the local Face ID enrollment metadata.

---

## Storage

- **Models** are downloaded automatically to your user config directory under `apm/faceid/models`.
- **Enrollment** metadata is stored next to the vault at `faceid/enrollment.json`.

---

## Typical Workflow

```bash
go build -tags faceid -o pm.exe
pm faceid enroll
pm faceid status
pm unlock
```

Face ID participates in the unlock path only when the binary was built with the `faceid` tag and enrollment data exists for the current vault.

---

## Notes

- Face ID uses the default camera (index `0`).
- If Face ID fails, you can always unlock with your master password.
- Native OpenCV and dlib requirements are the reason this feature is behind a build tag.
