#!/bin/bash

# Configuration
APP_NAME="SSHoebox"
BUNDLE_ID="com.sshoebox.app"
VERSION="1.2.0"
BUILD_DIR=".build/release"
DIST_DIR="dist"
APP_BUNDLE="${DIST_DIR}/${APP_NAME}.app"
LOGO_PATH="Sources/SSHoeboxApp/Resources/logo.png"

echo "🚀 Starting macOS App Bundling for ${APP_NAME}..."

# 1. Build in Release Mode
echo "🏗️  Building ${APP_NAME} in release mode..."
swift build -c release --disable-sandbox
if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

# 2. Create Bundle Structure
echo "📁 Creating app bundle structure..."
rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

# 3. Generate App Icon (.icns)
if [ -f "${LOGO_PATH}" ]; then
    echo "🎨 Generating App Icon (.icns)..."
    ICONSET_DIR="${DIST_DIR}/AppIcon.iconset"
    mkdir -p "${ICONSET_DIR}"
    
    # Generate various sizes using sips
    sips -z 16 16     "${LOGO_PATH}" --out "${ICONSET_DIR}/icon_16x16.png" > /dev/null 2>&1
    sips -z 32 32     "${LOGO_PATH}" --out "${ICONSET_DIR}/icon_16x16@2x.png" > /dev/null 2>&1
    sips -z 32 32     "${LOGO_PATH}" --out "${ICONSET_DIR}/icon_32x32.png" > /dev/null 2>&1
    sips -z 64 64     "${LOGO_PATH}" --out "${ICONSET_DIR}/icon_32x32@2x.png" > /dev/null 2>&1
    sips -z 128 128   "${LOGO_PATH}" --out "${ICONSET_DIR}/icon_128x128.png" > /dev/null 2>&1
    sips -z 256 256   "${LOGO_PATH}" --out "${ICONSET_DIR}/icon_128x128@2x.png" > /dev/null 2>&1
    sips -z 256 256   "${LOGO_PATH}" --out "${ICONSET_DIR}/icon_256x256.png" > /dev/null 2>&1
    sips -z 512 512   "${LOGO_PATH}" --out "${ICONSET_DIR}/icon_256x256@2x.png" > /dev/null 2>&1
    sips -z 512 512   "${LOGO_PATH}" --out "${ICONSET_DIR}/icon_512x512.png" > /dev/null 2>&1
    sips -z 1024 1024 "${LOGO_PATH}" --out "${ICONSET_DIR}/icon_512x512@2x.png" > /dev/null 2>&1
    
    # Convert iconset to icns
    iconutil -c icns "${ICONSET_DIR}" -o "${APP_BUNDLE}/Contents/Resources/AppIcon.icns"
    rm -rf "${ICONSET_DIR}"
    echo "✅ Generated AppIcon.icns"
else
    echo "⚠️  Logo not found at ${LOGO_PATH}. Skipping icon generation."
fi

# 4. Copy Executable
echo "📦 Copying executable..."
cp "${BUILD_DIR}/${APP_NAME}" "${APP_BUNDLE}/Contents/MacOS/"
chmod +x "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"

# 5. Generate Info.plist
echo "📝 Generating Info.plist..."
cat > "${APP_BUNDLE}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>4</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

# 6. Copy Resources (Bundles)
echo "🖼️  Copying resource bundles..."
if ls "${BUILD_DIR}"/*.bundle >/dev/null 2>&1; then
    cp -R "${BUILD_DIR}"/*.bundle "${APP_BUNDLE}/Contents/Resources/"
    echo "✅ Copied SPM resource bundles."
fi

# 7. Final Touch
echo "✅ Successfully bundled ${APP_NAME}.app with icon in the '${DIST_DIR}' directory!"
echo "✨ You can now move it to your /Applications folder."
