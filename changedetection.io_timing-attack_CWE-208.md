# Authentication Bypass via Substring Matching in check_authentication (CWE-287)

**BUG_Author:** herantong

**Affected Version:** changedetection.io ≤ 0.55.8

**Vendor:** [changedetection.io GitHub Repository](https://github.com/dgtlmoon/changedetection.io)

**Software:** [changedetection.io](https://github.com/dgtlmoon/changedetection.io)

**Vulnerability Files:**
- `changedetectionio/flask_app.py`
- `changedetectionio/auth_decorator.py`
- `changedetectionio/pluggy_interface.py`

---

## Description

### 1. Substring Matching in Authentication Bypass Check

The `check_authentication()` function registered as a global `@app.before_request` hook uses a substring check (`'login' in request.endpoint`) to exempt login-related endpoints from authentication. This allows any endpoint whose name contains the substring `login` to completely bypass authentication. For example, blueprint endpoints named `blueprint.login` or `mylogin` are accessible without authentication, constituting an access control bypass (CWE-287).

### 2. Vulnerable Code Location

The vulnerability is at `changedetectionio/flask_app.py:621` within the `check_authentication` function:

```python
# changedetectionio/flask_app.py:605-639
@app.before_request
def check_authentication():
    has_password_enabled = datastore.data['settings']['application'].get('password') or os.getenv("SALTED_PASS", False)

    if has_password_enabled and not flask_login.current_user.is_authenticated:
        if request.endpoint and request.endpoint == 'static_content' and request.view_args:
            return None
        elif request.endpoint and request.endpoint == 'static_flags':
            return None
        elif request.endpoint and request.endpoint == 'set_language':
            return None
        elif request.endpoint and 'login' in request.endpoint:  # <-- Vulnerable substring match on line 621
            return None
        elif request.endpoint in SHARED_DIFF_READ_ONLY_ENDPOINTS and datastore.data['settings']['application'].get('shared_diff_access'):
            return None
        elif request.method in flask_login.config.EXEMPT_METHODS:
            return None
        elif app.config.get('LOGIN_DISABLED'):
            return None
        elif request.blueprint == 'rss':
            return None
        elif request.path.startswith('/socket.io/'):
            return None
        elif request.path.startswith('/api/'):
            return None
        else:
            return login_manager.unauthorized()
```

All other endpoint exemptions in this function use exact matching (`==` or `in frozenset`). Line 621 is the only instance of substring matching in the entire authentication enforcement chain.

### 3. Prior Security Advisory Confirming the Pattern is Unsafe

The same codebase has already experienced and patched this exact class of vulnerability, as documented in `changedetectionio/auth_decorator.py:6-14`:

```python
# changedetectionio/auth_decorator.py:6-14
# Endpoints exempt from authentication when `shared_diff_access` is enabled.
# MUST be exact endpoint names -- substring matching (GHSA-vwgh-2hvh-4xm5)
# would let state-changing `/diff/<uuid>/extract` endpoints slip through
# because their names share the `diff_history_page` prefix.
SHARED_DIFF_READ_ONLY_ENDPOINTS = frozenset({
    'ui.ui_diff.diff_history_page',
    'ui.ui_diff.processor_asset',
    'ui.ui_diff.download_patch',
})
```

This comment explicitly acknowledges that substring matching caused a prior vulnerability (GHSA-vwgh-2hvh-4xm5), and mandates exact endpoint names as the fix. Despite this, the same substring matching pattern remained unfixed in `check_authentication()` at `flask_app.py:621`.

### 4. Exploitability via Plugin System

The pluggy plugin interface at `changedetectionio/pluggy_interface.py:212` allows plugins to dynamically register their own Flask routes via `@_app.route()`. A plugin could register a function named `login_plugin` or `mylogin`, and its endpoint would completely bypass authentication due to the substring check. Future code additions or blueprint integrations could also introduce exploitable endpoints.

### 5. Absence of Mitigations

- No additional middleware or reverse proxy validates endpoint names before requests reach `check_authentication`.
- No API gateway enforces authentication independently.
- The `login_manager.unauthorized()` fallback on line 639 is the only catch-all, and the substring check on line 621 is the sole mechanism preventing the login page from triggering an authentication redirect loop.

---

## Proof of Concept

### 1. Exploiting via Plugin Registration

A malicious or compromised plugin registers a route with a function name containing `login`:

```python
# In a plugin file loaded by pluggy_interface.py
@_app.route('/plugin_login_sensitive', methods=['GET'])
def plugin_login_sensitive():
    return "Sensitive data exposed without authentication"
```

Because the endpoint name `plugin_login_sensitive` contains the substring `login`, the `check_authentication` hook returns `None` without redirecting to the login page, granting unauthenticated access to the sensitive endpoint.

### 2. Exploiting via URL Access

```
GET http://<target-host>/plugin_login_sensitive
```

The response returns the sensitive data directly without requiring authentication, confirming the bypass.

### 3. Attack Flow

1. An attacker identifies or registers an endpoint whose Flask internal name contains the substring `login`.
2. The attacker sends an unauthenticated request to that endpoint.
3. `check_authentication()` evaluates `'login' in request.endpoint` as `True` and returns `None`, skipping authentication entirely.
4. The request reaches the handler and responds with protected content.

---

## Root Cause Analysis

| Question | Answer |
|---|---|
| Does the function enforce authentication? | Yes — `check_authentication` is a global `@app.before_request` hook enforcing authentication for all routes when password protection is enabled. |
| Does the authentication check use a known unsafe pattern? | Yes — `'login' in request.endpoint` is substring matching, a pattern already documented as unsafe in the same codebase (GHSA-vwgh-2hvh-4xm5). |
| Do other similar checks use exact matching? | Yes — all other endpoint exemptions in `check_authentication` use `==` or `in frozenset`. |
| Is the code in a test, demo, or dead-code context? | No — it is the live global authentication enforcement hook. |
| Can plugins or future code additions exploit this? | Yes — `pluggy_interface.py:212` allows dynamic route registration; any function name containing `login` bypasses authentication. |
| Are there other security mechanisms preventing exploitation? | No — no additional authentication middleware or gateway exists to catch this bypass. |

**Verdict: Confirmed vulnerability (CWE-287 — Improper Authentication).**

---

## Fix Recommendations

1. **Primary Fix**: Replace the substring check with exact endpoint matching at `changedetectionio/flask_app.py:621`:

   From:
   ```python
   elif request.endpoint and 'login' in request.endpoint:
   ```
   To:
   ```python
   elif request.endpoint and request.endpoint == 'login':
   ```
   If `logout` should also be exempt (to allow graceful redirect for unauthenticated users):
   ```python
   elif request.endpoint in {'login', 'logout'}:
   ```

2. **Consolidate Exempt Endpoints**: Merge all exempt endpoints into a single `frozenset` at module level, similar to `SHARED_DIFF_READ_ONLY_ENDPOINTS`, for easier auditing and maintenance.

3. **Add Regression Tests**: Add a test that verifies no substring matching is used for endpoint exemption in `check_authentication`. The test could parse the function's AST and assert all `request.endpoint` checks use exact equality or set membership.

4. **Audit Plugin Registration**: Ensure dynamically added routes from plugins do not inadvertently bypass authentication due to function names containing `login`.

---

## References

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [GHSA-vwgh-2hvh-4xm5](https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-vwgh-2hvh-4xm5) — Prior vulnerability in the same codebase caused by substring matching, already fixed in `auth_decorator.py`.
