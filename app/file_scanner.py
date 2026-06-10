"""
AI Sentinel — File Scanner

Detects malicious files through four independent signals:
  1. Magic byte validation — extension does not match actual format
  2. Shannon entropy analysis — high entropy signals encrypted/packed payload
  3. Macro marker detection — live VBA code inside OLE/Office documents
  4. PE-in-archive detection — executable binary hidden inside ZIP-based formats

Works on both file paths (disk) and raw bytes (network responses).
"""
import math
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Magic byte signatures
# ---------------------------------------------------------------------------
_MAGIC: list[tuple[bytes, str]] = [
    (b'\xff\xd8\xff',                    'jpeg'),
    (b'\x89PNG\r\n\x1a\n',               'png'),
    (b'GIF87a',                           'gif'),
    (b'GIF89a',                           'gif'),
    (b'%PDF',                             'pdf'),
    (b'PK\x03\x04',                       'zip'),
    (b'PK\x05\x06',                       'zip'),
    (b'MZ',                               'exe'),
    (b'\x7fELF',                          'elf'),
    (b'\xfe\xed\xfa\xce',                 'macho'),
    (b'\xfe\xed\xfa\xcf',                 'macho'),
    (b'\xce\xfa\xed\xfe',                 'macho'),
    (b'\xcf\xfa\xed\xfe',                 'macho'),
    (b'Rar!\x1a\x07',                     'rar'),
    (b'\x1f\x8b',                         'gz'),
    (b'BZh',                              'bz2'),
    (b'7z\xbc\xaf\x27\x1c',               '7z'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole'),
]

# Extensions that should never carry executable magic bytes
_INNOCENT_EXTS: frozenset[str] = frozenset({
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico', '.svg',
    '.pdf', '.txt', '.csv', '.json', '.xml', '.html', '.htm',
    '.md', '.log', '.conf', '.cfg', '.ini', '.yaml', '.yml',
})

# Extensions that allow macro execution when in OLE format
_MACRO_EXTS: frozenset[str] = frozenset({
    '.doc', '.xls', '.ppt', '.docm', '.xlsm', '.pptm',
    '.xlam', '.dotm', '.xltm', '.dotx', '.xltx', '.potm',
})

# Byte sequences that indicate live VBA macros inside an OLE container
_MACRO_MARKERS: list[bytes] = [
    b'VBA',
    b'AutoOpen',
    b'AutoExec',
    b'Auto_Open',
    b'Workbook_Open',
    b'Document_Open',
    b'Shell(',
    b'WScript.Shell',
    b'CreateObject',
]

# Known legitimate extensions for each magic type (used for mismatch check)
_EXPECTED_EXTS: dict[str, frozenset[str]] = {
    'jpeg': frozenset({'.jpg', '.jpeg'}),
    'png':  frozenset({'.png'}),
    'gif':  frozenset({'.gif'}),
    'pdf':  frozenset({'.pdf'}),
    'exe':  frozenset({'.exe', '.com', '.scr', '.pif', '.dll'}),
    'elf':  frozenset({'', '.so', '.out', '.bin'}),
    'gz':   frozenset({'.gz', '.tgz'}),
    'bz2':  frozenset({'.bz2', '.tbz2'}),
}

_ENTROPY_DANGER = 7.2   # bits/byte — signals encryption
_ENTROPY_WARN   = 6.5   # bits/byte — suspicious in document formats

_RISK_ORDER = {'clean': 0, 'suspicious': 1, 'dangerous': 2}


@dataclass
class FileScanResult:
    path: str
    risk: str                       # 'clean' | 'suspicious' | 'dangerous'
    reasons: list[str] = field(default_factory=list)
    entropy: float = 0.0
    magic_type: Optional[str] = None
    extension: str = ''
    size_bytes: int = 0


def _escalate(current: str, candidate: str) -> str:
    return candidate if _RISK_ORDER.get(candidate, 0) > _RISK_ORDER.get(current, 0) else current


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _detect_magic(data: bytes) -> Optional[str]:
    for magic_bytes, fmt in _MAGIC:
        if data[:len(magic_bytes)] == magic_bytes:
            return fmt
    return None


def _analyse(data: bytes, ext: str, size: int) -> FileScanResult:
    reasons: list[str] = []
    risk = 'clean'

    magic_type = _detect_magic(data)
    entropy    = _shannon(data[:65536])

    # Rule 1: executable magic bytes inside a file with a document extension
    if magic_type in ('exe', 'elf', 'macho') and ext in _INNOCENT_EXTS:
        reasons.append(f'executable magic ({magic_type}) inside {ext} file — likely disguised dropper')
        risk = _escalate(risk, 'dangerous')

    # Rule 2: OLE document — detect live VBA macro markers
    if magic_type == 'ole':
        hits = [m.decode('ascii', errors='replace') for m in _MACRO_MARKERS if m in data]
        if hits:
            reasons.append(f'OLE doc with active macro markers: {", ".join(hits[:4])}')
            risk = _escalate(risk, 'dangerous')
        elif ext in _MACRO_EXTS:
            reasons.append(f'macro-capable Office format ({ext})')
            risk = _escalate(risk, 'suspicious')

    # Rule 3: ZIP-based Office format (DOCX/XLSX) containing an embedded PE header
    if magic_type == 'zip' and ext in (_INNOCENT_EXTS | _MACRO_EXTS):
        if b'MZ' in data[512:]:
            reasons.append('ZIP-based document contains embedded PE (MZ) — possible dropper')
            risk = _escalate(risk, 'suspicious')

    # Rule 4: entropy — high entropy in non-archive files signals packed payload
    archive_types = {'zip', 'gz', 'bz2', 'rar', '7z'}
    if entropy >= _ENTROPY_DANGER and size > 1024:
        reasons.append(f'entropy {entropy:.2f} bit/byte exceeds {_ENTROPY_DANGER} — likely encrypted payload')
        risk = _escalate(risk, 'suspicious')
    elif (entropy >= _ENTROPY_WARN
            and magic_type not in archive_types
            and size > 4096
            and ext in _INNOCENT_EXTS):
        reasons.append(f'elevated entropy {entropy:.2f} bit/byte in document file')
        risk = _escalate(risk, 'suspicious')

    # Rule 5: extension mismatch
    expected = _EXPECTED_EXTS.get(magic_type or '')
    if expected and ext and ext not in expected:
        reasons.append(f'extension mismatch: file is {ext} but identified as {magic_type}')
        risk = _escalate(risk, 'suspicious')

    return FileScanResult(
        path='',
        risk=risk,
        reasons=reasons,
        entropy=round(entropy, 3),
        magic_type=magic_type,
        extension=ext,
        size_bytes=size,
    )


def scan_bytes(data: bytes, filename: str = '') -> FileScanResult:
    """Scan raw bytes (e.g., from a proxy-intercepted network response)."""
    ext    = Path(filename).suffix.lower() if filename else ''
    result = _analyse(data, ext, len(data))
    result.path = filename or '<network>'
    return result


def scan_file(path: str | Path, sample_bytes: int = 65536) -> FileScanResult:
    """Scan a file on disk, reading only the first sample_bytes for performance."""
    path = Path(path)
    ext  = path.suffix.lower()

    try:
        size = path.stat().st_size
    except OSError as e:
        return FileScanResult(str(path), 'clean', [f'stat error: {e}'], 0.0, None, ext, 0)

    if size == 0:
        return FileScanResult(str(path), 'clean', [], 0.0, None, ext, 0)

    try:
        with open(path, 'rb') as f:
            data = f.read(sample_bytes)
    except OSError as e:
        return FileScanResult(str(path), 'clean', [f'read error: {e}'], 0.0, None, ext, 0)

    result = _analyse(data, ext, size)
    result.path = str(path)
    return result


def scan_directory(directory: str | Path) -> list[FileScanResult]:
    """Scan every file in a directory; return only suspicious/dangerous results."""
    results = []
    for p in Path(directory).rglob('*'):
        if p.is_file():
            r = scan_file(p)
            if r.risk != 'clean':
                results.append(r)
    return results
