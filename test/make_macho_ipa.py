import sys, struct, zipfile, plistlib

def macho(filetype, with_old_sig=False):
    text_sect = struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT', 0x100001000, 0x100, 0x1000, 2, 0, 0, 0x80000400, 0, 0, 0)
    text = struct.pack('<II16sQQQQIIII', 0x19, 72 + 80, b'__TEXT', 0x100000000, 0x4000, 0, 0x4000, 5, 5, 1, 0) + text_sect
    le = struct.pack('<II16sQQQQIIII', 0x19, 72, b'__LINKEDIT', 0x100004000, 0x4000, 0x4000, 0x200, 1, 1, 0, 0)
    cmds = text + le
    hdr = struct.pack('<IIIIIIII', 0xfeedfacf, 0x0100000c, 0, filetype, 2, len(cmds), 0, 0)
    body = bytearray(0x4200)
    body[0:len(hdr)+len(cmds)] = hdr + cmds
    for i in range(0x1000, 0x1100): body[i] = (i * 7) & 0xff
    for i in range(0x4000, 0x4200): body[i] = 0xAB
    return bytes(body)

out = sys.argv[1]
info = {"CFBundleIdentifier": "com.example.demo", "CFBundleExecutable": "Demo", "CFBundleShortVersionString": "1.0", "CFBundleName": "Demo"}
fw = {"CFBundleIdentifier": "com.example.fw", "CFBundleExecutable": "Fw", "CFBundleName": "Fw"}
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    def add(n, d, mode=0o644):
        zi = zipfile.ZipInfo(n); zi.external_attr = (0o100000 | mode) << 16; zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, d)
    add("Payload/Demo.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
    add("Payload/Demo.app/Demo", macho(2), 0o755)
    add("Payload/Demo.app/PkgInfo", b"APPL????")
    add("Payload/Demo.app/en.lproj/Localizable.strings", b'"a"="b";')
    add("Payload/Demo.app/Frameworks/Fw.framework/Info.plist", plistlib.dumps(fw))
    add("Payload/Demo.app/Frameworks/Fw.framework/Fw", macho(6), 0o755)
    add("Payload/Demo.app/Frameworks/libx.dylib", macho(6), 0o755)
