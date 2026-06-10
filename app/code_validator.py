"""
AI Sentinel — Code Validator

AST-based safety gate for any Python code before it is executed.
Rejects: eval/exec, os.system, subprocess with shell=True, dangerous imports,
and other constructs that must never appear in auto-generated detection rules.

Also validates individual pattern strings (used for substring matching in the proxy)
to ensure they contain no embedded code or injection payloads.
"""
import ast

# ---------------------------------------------------------------------------
# Forbidden constructs
# ---------------------------------------------------------------------------

_FORBIDDEN_BUILTINS: frozenset[str] = frozenset({
    'eval', 'exec', 'compile', '__import__', 'open', 'breakpoint', 'input',
})

_FORBIDDEN_ATTR_CALLS: frozenset[tuple[str, str]] = frozenset({
    ('os',         'system'),
    ('os',         'popen'),
    ('os',         'execv'),
    ('os',         'execve'),
    ('os',         'execvp'),
    ('os',         'spawnl'),
    ('os',         'spawnle'),
    ('os',         'remove'),
    ('os',         'unlink'),
    ('subprocess', 'call'),
    ('subprocess', 'run'),
    ('subprocess', 'Popen'),
    ('subprocess', 'check_output'),
    ('subprocess', 'check_call'),
    ('ctypes',     'windll'),
    ('ctypes',     'cdll'),
    ('shutil',     'rmtree'),
    ('shutil',     'move'),
    ('shutil',     'copy'),
})

_FORBIDDEN_IMPORTS: frozenset[str] = frozenset({
    'ctypes', 'winreg', 'subprocess', 'shutil',
    'socket', 'requests', 'urllib', 'http',
})

# Tokens that must never appear in a plain pattern string
_PATTERN_FORBIDDEN_TOKENS: list[str] = [
    '__import__', '__builtins__', '__class__', '__globals__',
    'eval(', 'exec(', 'open(', 'compile(',
    'os.', 'sys.', 'import ', '\n', '\r',
]


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _SafetyVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.violations: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            if node.func.id in _FORBIDDEN_BUILTINS:
                self.violations.append(f'forbidden builtin: {node.func.id}()')

        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                pair = (node.func.value.id, node.func.attr)
                if pair in _FORBIDDEN_ATTR_CALLS:
                    self.violations.append(f'forbidden call: {pair[0]}.{pair[1]}()')
                # subprocess(..., shell=True) is dangerous regardless of the method
                if node.func.value.id == 'subprocess':
                    for kw in node.keywords:
                        if (kw.arg == 'shell'
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value is True):
                            self.violations.append('subprocess with shell=True')
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split('.')[0]
            if top in _FORBIDDEN_IMPORTS:
                self.violations.append(f'forbidden import: {alias.name}')
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            top = node.module.split('.')[0]
            if top in _FORBIDDEN_IMPORTS:
                self.violations.append(f'forbidden import: from {node.module}')
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_python(code: str) -> tuple[bool, list[str]]:
    """
    Parse and validate a Python code string against the safety rules.
    Returns (is_safe, violations).
    Empty violations list means the code is safe to execute.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, [f'syntax error: {e}']

    visitor = _SafetyVisitor()
    visitor.visit(tree)
    return len(visitor.violations) == 0, visitor.violations


def validate_pattern(pattern: str) -> tuple[bool, str]:
    """
    Validate a single detection pattern string (used for substring matching in
    the proxy and rule engine).  Must be plain printable ASCII with no embedded
    code or injection tokens.
    Returns (is_valid, reason_if_invalid).
    """
    if not isinstance(pattern, str):
        return False, 'not a string'
    if not pattern:
        return False, 'empty pattern'
    if len(pattern) > 200:
        return False, f'exceeds 200-char limit ({len(pattern)} chars)'
    if not all(0x20 <= ord(c) <= 0x7e for c in pattern):
        return False, 'contains non-printable or non-ASCII characters'
    for token in _PATTERN_FORBIDDEN_TOKENS:
        if token in pattern:
            return False, f'suspicious token: {repr(token)}'
    return True, ''
