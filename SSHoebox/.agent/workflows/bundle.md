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
- Drag and drop `SSHoebox.app` into your `/Applications` folder to install it permanently.

> [!NOTE]
> The bundling script builds the app in **Release Mode**, which enables full optimizations and is intended for daily use.
