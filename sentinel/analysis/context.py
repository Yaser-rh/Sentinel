"""Context analysis — AST-based import checking and code snippet extraction.

Handles per-package reachability analysis: determines if a vulnerable
dependency is actually imported and how it is used in the codebase.
"""

import ast
import os

# Common PyPI package name -> Python import name mappings
PACKAGE_IMPORT_MAP = {
    "pyyaml": "yaml",
    "pillow": "pil",
    "scikit-learn": "sklearn",
    "python-dateutil": "dateutil",
    "python-docx": "docx",
    "beautifulsoup4": "bs4",
    "mysql-python": "mysqldb",
    "flask-sqlalchemy": "flask_sqlalchemy",
    "flask-cors": "flask_cors",
    "pyjwt": "jwt",
    "python-dotenv": "dotenv",
    "google-generativeai": "google",
    "attrs": "attr",
    "opencv-python": "cv2",
    "pyzmq": "zmq",
    "msgpack-python": "msgpack",
}

# Known dangerous function calls per package (for usage analysis)
DANGEROUS_PATTERNS = {
    "yaml": ["yaml.load", "yaml.unsafe_load", "yaml.full_load"],
    "jwt": ["jwt.decode"],
    "pickle": ["pickle.loads", "pickle.load"],
    "subprocess": ["subprocess.call", "subprocess.Popen", "subprocess.run"],
    "os": ["os.system", "os.popen"],
    "eval": ["eval", "exec"],
    "sqlite3": ["cursor.execute", "db.execute"],
    "sqlalchemy": ["text(", "execute(", "raw_sql"],
    "flask": ["render_template_string", "make_response"],
    "jinja2": ["Environment(", "from_string"],
    "lxml": ["etree.parse", "etree.fromstring"],
    "xml": ["xml.etree.ElementTree.parse", "minidom.parseString"],
    "hashlib": ["hashlib.md5", "hashlib.sha1"],
    "requests": ["requests.get", "requests.post", "verify=False"],
    "werkzeug": ["secure_filename"],
    "tornado": ["WSGIContainer"],
}


class ContextAnalyzer:
    """AST-based code context analyzer.

    Provides import checking, code snippet extraction, and per-package
    usage analysis for vulnerability verification.
    """

    def __init__(self, target_dir):
        self.target_dir = target_dir

    # ── Import Checking ───────────────────────────────────────

    def check_import(self, library_name):
        """Check if a library is actually imported anywhere in the target directory.

        Uses AST parsing (not text search) for accuracy.

        Args:
            library_name: The PyPI package name to search for.

        Returns:
            bool: True if the library is imported in any .py file.
        """
        search_name = library_name.lower().replace("-", "_")
        mapped_name = PACKAGE_IMPORT_MAP.get(search_name)
        search_names = {search_name}
        if mapped_name:
            search_names.add(mapped_name.lower())
        search_parts = search_name.split("_")

        for root, _, files in os.walk(self.target_dir):
            relative_root = os.path.relpath(root, self.target_dir)
            if _should_skip_dir(relative_root):
                continue

            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            tree = ast.parse(f.read(), filename=file_path)

                        for node in ast.walk(tree):
                            if isinstance(node, ast.Import):
                                for alias in node.names:
                                    alias_lower = alias.name.lower().replace("-", "_")
                                    for sname in search_names:
                                        if sname in alias_lower or alias_lower in sname:
                                            return True
                                    if any(p in alias_lower and len(p) > 3 for p in search_parts):
                                        return True
                            elif isinstance(node, ast.ImportFrom):
                                if node.module:
                                    mod_lower = node.module.lower().replace("-", "_")
                                    for sname in search_names:
                                        if sname in mod_lower or mod_lower in sname:
                                            return True
                                    if any(p in mod_lower and len(p) > 3 for p in search_parts):
                                        return True
                    except Exception:
                        pass
        return False

    # ── Package Usage Analysis ────────────────────────────────

    def find_package_usage(self, package_name):
        """Find exactly WHERE and HOW a package is used in the codebase.

        Returns a structured text summary of all import statements and
        function call sites for the given package, with surrounding code context.

        Args:
            package_name: The PyPI package name to analyze.

        Returns:
            str: A human-readable summary of usage locations and patterns.
        """
        search_name = package_name.lower().replace("-", "_")
        mapped_name = PACKAGE_IMPORT_MAP.get(search_name, search_name)

        import_lines = []
        call_sites = []
        dangerous_calls = []

        # Get known dangerous patterns for this package
        dangerous_fns = set()
        for key in (search_name, mapped_name):
            if key in DANGEROUS_PATTERNS:
                dangerous_fns.update(DANGEROUS_PATTERNS[key])

        for root, _, files in os.walk(self.target_dir):
            relative_root = os.path.relpath(root, self.target_dir)
            if _should_skip_dir(relative_root):
                continue

            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.target_dir)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            source_lines = f.readlines()
                            source = "".join(source_lines)

                        # Find imports via AST
                        tree = ast.parse(source, filename=file_path)
                        imported_names = set()

                        for node in ast.walk(tree):
                            if isinstance(node, ast.Import):
                                for alias in node.names:
                                    if _name_matches(alias.name, search_name, mapped_name):
                                        lineno = node.lineno
                                        line_text = source_lines[lineno - 1].strip() if lineno <= len(source_lines) else ""
                                        import_lines.append(f"  {rel_path}:{lineno}: {line_text}")
                                        imported_names.add(alias.asname or alias.name.split(".")[-1])

                            elif isinstance(node, ast.ImportFrom):
                                if node.module and _name_matches(node.module, search_name, mapped_name):
                                    lineno = node.lineno
                                    line_text = source_lines[lineno - 1].strip() if lineno <= len(source_lines) else ""
                                    import_lines.append(f"  {rel_path}:{lineno}: {line_text}")
                                    for alias in (node.names or []):
                                        imported_names.add(alias.asname or alias.name)

                        if not imported_names:
                            continue

                        # Find function call sites using those imported names
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call):
                                call_str = _get_call_string(node)
                                if call_str and any(name in call_str for name in imported_names):
                                    lineno = node.lineno
                                    line_text = source_lines[lineno - 1].strip() if lineno <= len(source_lines) else ""

                                    # Check if this is a dangerous pattern
                                    is_dangerous = any(dp in call_str for dp in dangerous_fns) if dangerous_fns else False

                                    entry = f"  {rel_path}:{lineno}: {line_text}"
                                    if is_dangerous:
                                        entry += "  ← DANGEROUS"
                                        dangerous_calls.append(entry)
                                    call_sites.append(entry)

                    except Exception:
                        pass

        # Build the summary
        if not import_lines:
            return f"Package '{package_name}' is not directly imported (may be a transitive dependency)."

        parts = [f"Package '{package_name}' usage:"]
        parts.append(f"  Imports ({len(import_lines)}):")
        parts.extend(import_lines[:5])

        if call_sites:
            parts.append(f"  Call sites ({len(call_sites)}):")
            parts.extend(call_sites[:10])

        if dangerous_calls:
            parts.append(f"  ⚠ Dangerous patterns found ({len(dangerous_calls)}):")
            parts.extend(dangerous_calls[:5])

        return "\n".join(parts)

    # ── Snippet Extraction ────────────────────────────────────

    def get_snippet(self, file_path, line_number, context_lines=5):
        """Extract a snippet of code around a specific line.

        Args:
            file_path: Absolute path to the source file.
            line_number: The target line number (1-indexed).
            context_lines: Number of lines before/after to include.

        Returns:
            str: The code snippet, or empty string on failure.
        """
        if not os.path.exists(file_path):
            return ""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            start = max(0, line_number - 1 - context_lines)
            end = min(len(lines), line_number + context_lines)
            return "".join(lines[start:end])
        except Exception:
            return ""


# ── Module-level helpers ──────────────────────────────────────

def _should_skip_dir(relative_root):
    """Check if a directory should be skipped during analysis."""
    return (
        (relative_root.startswith(".") and relative_root != ".")
        or "venv" in relative_root.lower()
        or "node_modules" in relative_root
        or "__pycache__" in relative_root
    )


def _name_matches(import_name, search_name, mapped_name):
    """Check if an import name matches the package we're looking for."""
    name_lower = import_name.lower().replace("-", "_")
    return (
        search_name in name_lower
        or name_lower in search_name
        or mapped_name in name_lower
        or name_lower in mapped_name
    )


def _get_call_string(call_node):
    """Reconstruct a rough call string from an AST Call node."""
    try:
        if isinstance(call_node.func, ast.Attribute):
            # e.g., yaml.load(...)
            if isinstance(call_node.func.value, ast.Name):
                return f"{call_node.func.value.id}.{call_node.func.attr}"
            elif isinstance(call_node.func.value, ast.Attribute):
                # nested: e.g., etree.ElementTree.parse
                return f"...{call_node.func.attr}"
        elif isinstance(call_node.func, ast.Name):
            # e.g., eval(...)
            return call_node.func.id
    except Exception:
        pass
    return None
