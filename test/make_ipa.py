import sys, zipfile, plistlib
out, fmt = sys.argv[1], sys.argv[2]
info = {"CFBundleIdentifier": "com.example.Тест&App", "CFBundleShortVersionString": "1.2.3", "CFBundleDisplayName": "Demo <App>"}
data = plistlib.dumps(info, fmt=plistlib.FMT_BINARY if fmt == "bin" else plistlib.FMT_XML)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("Payload/Demo.app/Frameworks/X.framework/Info.plist", plistlib.dumps({"CFBundleIdentifier": "wrong"}))
    z.writestr("Payload/Demo.app/Info.plist", data)
    z.writestr("Payload/Demo.app/Demo", b"\0" * 5000)
