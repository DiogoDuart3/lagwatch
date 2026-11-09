#!/bin/sh
# Builds Lagwatch.app and installs it into /Applications.
# With --no-install it only builds target/Lagwatch.app.
set -eu
cd "$(dirname "$0")"

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

cargo build --release

app=target/Lagwatch.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp target/release/lagwatch "$app/Contents/MacOS/lagwatch"

# macOS wants the icon as an .icns holding every size it might draw.
iconset=target/Lagwatch.iconset
rm -rf "$iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" assets/icon.png --out "$iconset/icon_${size}x${size}.png" >/dev/null
    sips -z "$((size * 2))" "$((size * 2))" assets/icon.png --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/Lagwatch.icns"

cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Lagwatch</string>
    <key>CFBundleDisplayName</key>
    <string>Lagwatch</string>
    <key>CFBundleIdentifier</key>
    <string>com.diogoduarte.lagwatch</string>
    <key>CFBundleExecutable</key>
    <string>lagwatch</string>
    <key>CFBundleIconFile</key>
    <string>Lagwatch</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>VERSION</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST
sed -i '' "s/VERSION/$version/" "$app/Contents/Info.plist"
# Files touched by sips carry extended attributes that codesign rejects.
xattr -cr "$app"
codesign --force --sign - "$app"

[ "${1:-}" = "--no-install" ] && exit 0

rm -rf /Applications/Lagwatch.app
cp -R "$app" /Applications/Lagwatch.app
echo "Installed /Applications/Lagwatch.app"
