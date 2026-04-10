---
description: how to bundle the application as a macOS stand-alone app
---

This workflow explains how to build and package SSHoebox into a standard macOS `.app` bundle.

1. Ensure all your changes are committed.
// turbo
2. Run the bundling script:
```bash
./scripts/bundle_app.sh
```

3. Locate the bundled application:
The resulting app will be available at:
`dist/SSHoebox.app`

4. Verify and Install:
- Double-click `dist/SSHoebox.app` to test it.
- Or install to Applications:
```bash
sudo cp -r dist/SSHoebox.app /Applications/
```

> [!NOTE]
> The bundling script builds the app in **Release Mode**, which enables full optimizations and is intended for daily use.

> [!NOTE]
> `SQLCipher.framework` is automatically embedded into `Contents/Frameworks/` by the script. You do not need to do anything extra — the app will launch correctly from `/Applications` without any "Library not loaded" errors.
