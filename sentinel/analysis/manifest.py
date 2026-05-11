"""Project manifest generation — AST-based project profiling.

Generates a compact manifest describing the project's framework, entry points,
routes, imports, and security patterns. Used to give the AI rich context
about the project being scanned.
"""

import ast
import os


class ProjectManifest:
    """Generates a project profile via AST analysis.

    Scans all Python files in the target directory to detect the web
    framework, entry points, routes, imported packages, and common
    security-sensitive code patterns.
    """

    def __init__(self, target_dir):
        self.target_dir = target_dir
        self._manifest = None  # cached after first generation

    def generate(self):
        """Generate the project manifest.

        Returns:
            dict: Manifest with keys: framework, entry_points, total_files,
                  total_lines, routes, imports_used, security_patterns,
                  classes, key_functions.
        """
        if self._manifest:
            return self._manifest

        manifest = {
            "framework": "Unknown",
            "entry_points": [],
            "total_files": 0,
            "total_lines": 0,
            "routes": [],
            "imports_used": set(),
            "security_patterns": {
                "hardcoded_secrets": False,
                "sql_raw_queries": False,
                "template_rendering": False,
                "file_uploads": False,
                "deserialization": False,
                "shell_commands": False,
                "weak_hashing": False,
            },
            "classes": [],
            "key_functions": [],
        }

        for root, _, files in os.walk(self.target_dir):
            relative_root = os.path.relpath(root, self.target_dir)
            if _should_skip_dir(relative_root):
                continue

            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.target_dir)
                    manifest["total_files"] += 1

                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            source = f.read()
                        lines = source.split("\n")
                        manifest["total_lines"] += len(lines)
                        tree = ast.parse(source, filename=file_path)
                        _analyze_file_ast(tree, source, rel_path, manifest)
                    except Exception:
                        pass

        # Detect framework
        imports = manifest["imports_used"]
        if "flask" in imports:
            manifest["framework"] = "Flask"
        elif "django" in imports:
            manifest["framework"] = "Django"
        elif "fastapi" in imports:
            manifest["framework"] = "FastAPI"

        # Detect entry points
        for root, _, files in os.walk(self.target_dir):
            relative_root = os.path.relpath(root, self.target_dir)
            if _should_skip_dir(relative_root):
                continue
            for file in files:
                if file in ("app.py", "main.py", "wsgi.py", "manage.py", "server.py"):
                    manifest["entry_points"].append(
                        os.path.relpath(os.path.join(root, file), self.target_dir)
                    )

        # Convert set to sorted list for JSON serialization
        manifest["imports_used"] = sorted(manifest["imports_used"])
        # Trim to keep token count low
        manifest["routes"] = manifest["routes"][:20]
        manifest["key_functions"] = manifest["key_functions"][:15]
        manifest["classes"] = manifest["classes"][:10]

        self._manifest = manifest
        return manifest

    def get_summary(self):
        """Return a concise text summary of the project manifest for AI prompts.

        Returns:
            str: Multi-line summary suitable for inclusion in an AI prompt.
        """
        m = self.generate()
        lines = [
            f"Framework: {m['framework']} | Files: {m['total_files']} | Lines: {m['total_lines']}",
            f"Entry points: {', '.join(m['entry_points']) or 'N/A'}",
            f"Imports: {', '.join(m['imports_used'][:20])}",
        ]
        if m["routes"]:
            lines.append(f"Routes: {', '.join(m['routes'][:10])}")
        if m["classes"]:
            lines.append(f"Classes: {', '.join(m['classes'][:10])}")

        # Security flags
        flags = [k.replace("_", " ") for k, v in m["security_patterns"].items() if v]
        if flags:
            lines.append(f"Security concerns detected: {', '.join(flags)}")

        return "\n".join(lines)


# ── Module-level helpers ──────────────────────────────────────

def _should_skip_dir(relative_root):
    """Check if a directory should be skipped during analysis."""
    return (
        (relative_root.startswith(".") and relative_root != ".")
        or "venv" in relative_root.lower()
        or "node_modules" in relative_root
        or "__pycache__" in relative_root
    )


def _analyze_file_ast(tree, source, rel_path, manifest):
    """Extract imports, routes, classes, functions, and security patterns from one file."""
    source_lower = source.lower()

    for node in ast.walk(tree):
        # ── Imports ──
        if isinstance(node, ast.Import):
            for alias in node.names:
                manifest["imports_used"].add(alias.name.split(".")[0].lower())
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                manifest["imports_used"].add(node.module.split(".")[0].lower())

        # ── Classes ──
        elif isinstance(node, ast.ClassDef):
            manifest["classes"].append(node.name)

        # ── Functions & Routes ──
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            manifest["key_functions"].append(node.name)
            # Check for route decorators
            for dec in node.decorator_list:
                dec_str = ast.dump(dec)
                if "route" in dec_str.lower() or "get" in dec_str.lower() or "post" in dec_str.lower():
                    route = _extract_route_path(dec)
                    if route:
                        manifest["routes"].append(route)

    # ── Security pattern detection (string-based for speed) ──
    if "secret" in source_lower and ("=" in source_lower):
        manifest["security_patterns"]["hardcoded_secrets"] = True
    if "execute(" in source_lower or "raw(" in source_lower or "text(" in source_lower:
        manifest["security_patterns"]["sql_raw_queries"] = True
    if "render_template_string" in source_lower:
        manifest["security_patterns"]["template_rendering"] = True
    if "upload" in source_lower or "save(" in source_lower:
        manifest["security_patterns"]["file_uploads"] = True
    if "pickle" in source_lower or "yaml.load" in source_lower or "marshal" in source_lower:
        manifest["security_patterns"]["deserialization"] = True
    if "os.system" in source_lower or "subprocess" in source_lower or "popen" in source_lower:
        manifest["security_patterns"]["shell_commands"] = True
    if "md5" in source_lower or "sha1" in source_lower:
        manifest["security_patterns"]["weak_hashing"] = True


def _extract_route_path(decorator_node):
    """Try to extract a route path string from a decorator AST node."""
    try:
        if isinstance(decorator_node, ast.Call):
            if decorator_node.args:
                arg = decorator_node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
    except Exception:
        pass
    return None
