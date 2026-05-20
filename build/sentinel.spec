# PyInstaller spec for AI Sentinel
# Build: pyinstaller build/sentinel.spec --distpath dist --workpath build/work
#
# Output: dist/AIsentinel/AIsentinel.exe
# The entire dist/AIsentinel/ folder is self-contained — no Python needed.

import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent   # AI_Sentinel root

block_cipher = None

a = Analysis(
    [str(ROOT / 'privacy' / 'privacy_main.py')],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        # Include all Python source packages so imports work at runtime
        (str(ROOT / 'privacy'),  'privacy'),
        (str(ROOT / 'app'),      'app'),
        (str(ROOT / 'model'),    'model'),
        # App icon
        (str(ROOT / 'assets' / 'sentinel.ico'), 'assets'),
    ],
    hiddenimports=[
        # mitmproxy pulls in a lot of dynamic imports
        'mitmproxy',
        'mitmproxy.proxy',
        'mitmproxy.addons',
        'mitmproxy.http',
        'mitmproxy.ctx',
        'mitmproxy.net',
        'mitmproxy.io',
        'mitmproxy.contentviews',
        'mitmproxy.coretypes',
        'mitmproxy.options',
        'mitmproxy.proxy.layers',
        'mitmproxy.proxy.server',
        # cryptography
        'cryptography',
        'cryptography.hazmat.backends',
        'cryptography.hazmat.primitives.asymmetric.ed25519',
        # passlib / bcrypt
        'passlib',
        'passlib.handlers',
        'passlib.handlers.bcrypt',
        'bcrypt',
        # pystray + PIL
        'pystray',
        'pystray._win32',
        'pystray._darwin',
        'PIL',
        'PIL.Image',
        'PIL.ImageDraw',
        'PIL.ImageFont',
        # plyer notifications
        'plyer',
        'plyer.platforms',
        'plyer.platforms.win',
        'plyer.platforms.win.notification',
        'plyer.platforms.macosx',
        'plyer.platforms.macosx.notification',
        # other deps
        'requests',
        'dotenv',
        'sklearn',
        'joblib',
        'numpy',
        'pandas',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'unittest', 'pydoc'],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AIsentinel',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,           # no terminal window — tray-only app
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / 'assets' / 'sentinel.ico'),
    version_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='AIsentinel',
)
