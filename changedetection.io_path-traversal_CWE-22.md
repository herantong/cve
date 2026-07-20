# Path Traversal in static_content Screenshot Handler (CWE-22)

**BUG_Author:** herantong

**Affected Version:** changedetection.io ≤ 0.55.8

**Vendor:** [changedetection.io GitHub Repository](https://github.com/dgtlmoon/changedetection.io)

**Software:** [changedetection.io](https://github.com/dgtlmoon/changedetection.io)

**Vulnerability Files:**
- `changedetectionio/flask_app.py`
- `changedetectionio/blueprint/backups/__init__.py`

---

## Description

### 1. Path Traversal via Unsanitized Filename Parameter

The `static_content()` handler at `/static/<string:group>/<string:filename>` uses the unvalidated `filename` route parameter to construct a directory path via `os.path.join(datastore_o.datastore_path, filename)`. When `group` is `screenshot`, the resulting path is passed directly as the **directory** argument to `send_from_directory()`. An attacker can provide traversal sequences (e.g., `..` or `..\other_watch_uuid`) to escape the intended datastore directory and read screenshot files belonging to other watches or arbitrary directories (CWE-22).

### 2. Vulnerable Code Location

The vulnerability is in `changedetectionio/flask_app.py`, starting at line 819:

```python
# changedetectionio/flask_app.py:819
@app.route("/static/<string:group>/<string:filename>", methods=['GET'])
def static_content(group, filename):
    from flask import make_response
    import re

    group = re.sub(r'[^a-z0-9_-]+', '', group.lower())
    filename = filename  # <-- NO sanitization applied to filename

    if not group or not filename:
        abort(404)

    if group == 'screenshot':
        if datastore.data['settings']['application']['password'] and not flask_login.current_user.is_authenticated:
            if not datastore.data['settings']['application'].get('shared_diff_access'):
                abort(403)

        screenshot_filename = "last-screenshot.png" if not request.args.get('error_screenshot') else "last-error-screenshot.png"

        try:
            response = make_response(send_from_directory(os.path.join(datastore_o.datastore_path, filename), screenshot_filename))
```

The `group` parameter is sanitized with a regex that strips dots and slashes (`[^a-z0-9_-]+`), but `filename` receives no filtering whatsoever (`filename = filename` is a no-op). It is then used to construct the **directory** argument for `send_from_directory()`. Flask's `send_from_directory` validates that the requested file resides within the given directory, but does **not** validate that the directory itself is safe.

### 3. Same Unsafe Pattern in visual_selector_data

The `visual_selector_data` branch at line 886 exhibits the identical vulnerability:

```python
# changedetectionio/flask_app.py:886
watch_directory = str(os.path.join(datastore_o.datastore_path, filename))
response = make_response(send_from_directory(watch_directory, "elements.deflate"))
```

### 4. Safe Pattern Elsewhere in the Same Codebase

The backup download handler in `changedetectionio/blueprint/backups/__init__.py` demonstrates the correct approach:

```python
# changedetectionio/blueprint/backups/__init__.py:158-166
if not re.match(r"^" + backup_filename_regex + "$", filename):
    abort(400)

full_path = os.path.join(os.path.abspath(datastore.datastore_path), filename)
if not full_path.startswith(os.path.abspath(datastore.datastore_path) + os.sep):
    abort(404)

return send_from_directory(os.path.abspath(datastore.datastore_path), filename, as_attachment=True)
```

This handler: (1) validates the filename against a regex whitelist, (2) computes the absolute path, (3) verifies the resolved path stays within the base directory, and (4) passes a **safe base directory** to `send_from_directory`. The screenshot handler omits all four steps.

### 5. Authentication Context

```python
# changedetectionio/flask_app.py:832-836
if group == 'screenshot':
    if datastore.data['settings']['application']['password'] and not flask_login.current_user.is_authenticated:
        if not datastore.data['settings']['application'].get('shared_diff_access'):
            abort(403)
```

When no application password is configured or `shared_diff_access` is enabled, the endpoint is accessible without authentication. Under these configurations, unauthenticated attackers can exploit this vulnerability.

### 6. Route Converter Behavior

Flask's `<string:filename>` converter blocks forward slashes (`/`) but does **not** block backslashes (`\`). On Windows, `os.path.join` uses backslashes as the path separator, so a payload like `..\other_watch_uuid` is accepted by the router and traverses directories. On Linux, `..` payloads traverse to the parent of `datastore_path`.

---

## Proof of Concept

### 1. Traverse to Another Watch's Screenshot

Request a screenshot from a different watch UUID by traversing out of the current directory:

```
GET http://<target-host>/static/screenshot/../<other_watch_uuid>
```

### 2. Traverse to Arbitrary Filesystem Locations

On Linux, traverse upward multiple levels to reach system files:

```
GET http://<target-host>/static/screenshot/../../../../etc/passwd
```

### 3. Attack Flow

1. An attacker identifies the `static_content` endpoint.
2. The attacker crafts a URL with traversal sequences in the `filename` parameter.
3. Flask's router accepts the payload because `<string:filename>` does not block `..` or `\`.
4. `os.path.join(datastore_o.datastore_path, filename)` resolves to a directory outside the intended datastore.
5. `send_from_directory()` serves the requested screenshot file from the escaped directory.
6. The attacker exfiltrates screenshots belonging to other monitored URLs or arbitrary files accessible to the process.

### 4. Existing Test Hints at Traversal Abuse

The test suite at `changedetectionio/tests/test_security.py:42-55` already includes traversal-like test cases, indicating awareness of the attack surface, though they target the generic static file fallback rather than the screenshot branch:

```python
res = client.get(url_for('static_content', group='..', filename='__init__.py'))
res = client.get(url_for('static_content', group='.', filename='../__init__.py'))
```

---

## Root Cause Analysis

| Question | Answer |
|---|---|
| Does user-controlled input influence a file path? | Yes — `filename` is a Flask route parameter (`<string:filename>`) taken directly from the HTTP request URL. |
| Is the path normalized and validated against a base directory? | No — no `os.path.realpath()`, `os.path.abspath()`, or `startswith(base)` check exists before `send_from_directory`. |
| Is `basename()` used to strip directory components? | No — `filename = filename` is a no-op; the raw value is used directly. |
| Is there an effective filename whitelist? | No — no regex, UUID validation, or whitelist is applied to `filename` in the screenshot branch. |
| Is the code in a test, demo, or dead-code context? | No — it is a live production route handler. |
| Does the same codebase demonstrate the correct safe pattern? | Yes — `blueprint/backups/__init__.py:161-163` uses `realpath` + `startswith(base_dir)`, proving the screenshot handler lacks necessary defenses. |

**Verdict: Confirmed vulnerability (CWE-22 — Path Traversal).**

---

## Fix Recommendations

1. **Sanitize `filename` Before Path Construction**: Apply the same regex filter used for `group`, or use an explicit UUID regex if screenshots are stored in watch UUID directories:
   ```python
   filename = re.sub(r'[^a-zA-Z0-9_-]+', '', filename)
   ```

2. **Add Normalization and Base Directory Validation**: After joining, compute the absolute path and verify it remains within the datastore root:
   ```python
   watch_dir = os.path.abspath(os.path.join(datastore_o.datastore_path, filename))
   if not watch_dir.startswith(os.path.abspath(datastore_o.datastore_path) + os.sep):
       abort(404)
   response = make_response(send_from_directory(watch_dir, screenshot_filename))
   ```

3. **Use `os.path.basename()` or Strict Whitelist**: If `filename` should only be a watch UUID, validate it against a UUID regex before use.

4. **Apply the Same Fix to `visual_selector_data`**: The identical unsafe pattern at line 886 must be hardened consistently.

5. **Enforce Safe `send_from_directory` Usage**: Ensure `send_from_directory` is always called with a fixed, safe base directory, and that only the file name portion is user-controlled.

---

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [Flask `send_from_directory` documentation](https://flask.palletsprojects.com/en/stable/api/#flask.send_from_directory)
