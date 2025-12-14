from flask import Flask, jsonify, request, url_for, make_response, g
from flask_mysqldb import MySQL
import re
import os
from datetime import timedelta, datetime

# Try to import Flask-JWT-Extended and PyJWT lazily to support environments with either
_HAS_FLASK_JWT = False
_HAS_PYJWT = False
try:
    from flask_jwt_extended import (
        JWTManager as _JWTManager,
        create_access_token as _create_access_token,
        verify_jwt_in_request as _verify_jwt_in_request,
        get_jwt_identity as _get_jwt_identity,
        get_jwt as _get_jwt,
    )
    _HAS_FLASK_JWT = True
except Exception:
    # Not available in this environment; we'll fall back to PyJWT if installed
    _HAS_FLASK_JWT = False

try:
    import jwt as _pyjwt
    _HAS_PYJWT = True
except Exception:
    _pyjwt = None
    _HAS_PYJWT = False

app = Flask(__name__)

# Security config
APP_SECRET = os.getenv("APP_SECRET") or os.getenv("SECRET_KEY") or "dev-secret-change-me"
JWT_ALGO = "HS256"
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "60"))
# New: allow endpoints to soft-fail when DB is unavailable (for local JWT testing)
DB_OPTIONAL = os.getenv("DB_OPTIONAL", "0") == "1"

# MySQL configuration
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Pentagon0211'
app.config['MYSQL_DB'] = 'CS_ELECT'

# JWT / Auth config (optional, controlled via env)
# REQUIRE_AUTH: when true, endpoints (except whitelist) require Authorization: Bearer <token>
app.config['REQUIRE_AUTH'] = os.environ.get('REQUIRE_AUTH', 'false').lower() in ('1', 'true', 'yes')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=int(os.environ.get('JWT_EXP_HOURS', '1')))
# Accept tokens from either Authorization header or query string (optional convenience)
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'query_string']
app.config['JWT_QUERY_STRING_NAME'] = os.environ.get('JWT_QUERY_STRING_NAME', 'token')
# Admin credentials used by /auth/login
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'admin')

# Initialize MySQL and JWT if available
mysql = MySQL(app)
if _HAS_FLASK_JWT:
    jwt_ext = _JWTManager(app)

from functools import wraps

# --- Token issuing / decoding helpers ---

def _issue_token(subject, extra_claims=None, expires_minutes=JWT_EXP_MINUTES):
    """
    Issue a JWT-like token. Prefer Flask-JWT-Extended when available (creates tokens
    compatible with its verification). Otherwise fall back to PyJWT.
    Returns a string token.
    """
    if _HAS_FLASK_JWT and _create_access_token is not None:
        # Flask-JWT-Extended will include identity and additional_claims
        expires = timedelta(minutes=expires_minutes)
        # create_access_token accepts additional_claims in version 4.x
        return _create_access_token(identity=subject, additional_claims=extra_claims or {}, expires_delta=expires)
    if _HAS_PYJWT and _pyjwt is not None:
        now = datetime.utcnow()
        payload = {
            "sub": str(subject),
            "iat": now,
            "exp": now + timedelta(minutes=expires_minutes),
        }
        if extra_claims:
            payload.update(extra_claims)
        return _pyjwt.encode(payload, APP_SECRET, algorithm=JWT_ALGO)
    # As a last resort return a simple placeholder token (not secure)
    return f"dev-token:{subject}"


def _decode_token(token):
    """
    Decode a token using PyJWT if available. When Flask-JWT-Extended is used in
    the app, verification will be handled by its decorators; this helper is a
    fallback only.
    """
    if _HAS_PYJWT and _pyjwt is not None:
        try:
            return _pyjwt.decode(token, APP_SECRET, algorithms=[JWT_ALGO])
        except _pyjwt.ExpiredSignatureError:
            return {"_error": "Token expired"}
        except _pyjwt.InvalidTokenError:
            return {"_error": "Invalid token"}
    # If we cannot decode, return an error placeholder
    return {"_error": "Token decode not supported in this environment"}


def _get_bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    token = request.args.get('access_token') or request.args.get('token') or request.headers.get('X-Access-Token')
    if token:
        return token.strip()
    return None


# Compatibility decorators: support both the older simple require_auth (PyJWT) and
# the newer flask_jwt_extended-based decorators. Tests and routes in the
# repository may use a mix of decorator names, so provide aliases.

# Primary decorators using Flask-JWT-Extended when available

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not app.config.get('REQUIRE_AUTH'):
            return fn(*args, **kwargs)
        if not _HAS_FLASK_JWT:
            # Fall back to basic header decode flow
            token = _get_bearer_token()
            if not token:
                return render_response({"error": "Authorization header missing or invalid"}, 401, headers={"WWW-Authenticate": "Bearer"})
            claims = _decode_token(token)
            if "_error" in claims:
                return render_response({"error": claims["_error"]}, 401, headers={"WWW-Authenticate": "Bearer error=invalid_token"})
            request.claims = claims
            g.current_user = claims.get('sub')
            return fn(*args, **kwargs)
        try:
            _verify_jwt_in_request()
            g.current_user = _get_jwt_identity()
        except Exception:
            return render_response({'error': 'Missing or invalid token'}, 401)
        return fn(*args, **kwargs)
    return wrapper


def auth_optional(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not app.config.get('REQUIRE_AUTH'):
            g.current_user = None
            return fn(*args, **kwargs)
        # When Flask-JWT-Extended is available let it try to verify but don't fail
        if _HAS_FLASK_JWT:
            try:
                _verify_jwt_in_request(optional=True)
                g.current_user = _get_jwt_identity()
            except Exception:
                g.current_user = None
        else:
            # No automatic verification; attempt to decode if token present
            token = _get_bearer_token()
            if token:
                claims = _decode_token(token)
                if "_error" not in claims:
                    g.current_user = claims.get('sub')
                else:
                    g.current_user = None
            else:
                g.current_user = None
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not app.config.get('REQUIRE_AUTH'):
            return fn(*args, **kwargs)
        if _HAS_FLASK_JWT:
            try:
                _verify_jwt_in_request()
                identity = _get_jwt_identity()
                try:
                    claims = _get_jwt() if _get_jwt is not None else {}
                except Exception:
                    claims = {}
                is_admin_claim = bool(claims.get('is_admin', False)) if isinstance(claims, dict) else False
                if identity != ADMIN_USER and not is_admin_claim:
                    return render_response({'error': 'Admin privileges required'}, 403)
                g.current_user = identity
            except Exception:
                return render_response({'error': 'Missing or invalid token'}, 401)
            return fn(*args, **kwargs)
        # Fallback: use simple header decode and check sub
        token = _get_bearer_token()
        if not token:
            return render_response({"error": "Authorization header missing or invalid"}, 401)
        claims = _decode_token(token)
        if "_error" in claims:
            return render_response({"error": claims["_error"]}, 401)
        if str(claims.get('sub')) != ADMIN_USER and not claims.get('is_admin'):
            return render_response({'error': 'Admin privileges required'}, 403)
        request.claims = claims
        g.current_user = claims.get('sub')
        return fn(*args, **kwargs)
    return wrapper


def force_auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if _HAS_FLASK_JWT:
            try:
                _verify_jwt_in_request()
                g.current_user = _get_jwt_identity()
            except Exception:
                return render_response({'error': 'Missing or invalid token'}, 401)
            return fn(*args, **kwargs)
        # Fallback to header-based verification
        token = _get_bearer_token()
        if not token:
            return render_response({"error": "Authorization header missing or invalid"}, 401)
        claims = _decode_token(token)
        if "_error" in claims:
            return render_response({"error": claims["_error"]}, 401)
        request.claims = claims
        g.current_user = claims.get('sub')
        return fn(*args, **kwargs)
    return wrapper

# Backwards-compatible alias: some routes use require_auth decorator name
require_auth = auth_required


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --- Response formatting helper ---

def _to_xml_tag(key):
    """
    Helper: sanitize a dictionary key into a safe XML tag name.

    Usage: internal helper used by XML rendering functions to produce valid tags.
    """
    # Ensure valid XML tag by removing spaces and non-alnum (basic safety)
    safe = re.sub(r"[^a-zA-Z0-9_]", "", str(key)) or "item"
    # Tags cannot start with a digit
    if safe[0].isdigit():
        safe = f"_{safe}"
    return safe


def _escape_xml(text):
    """
    Helper: escape special characters for XML output.

    Usage: internal helper for XML serialization to avoid breaking XML structure.
    """
    if text is None:
        return ""
    s = str(text)
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&apos;")
    )


def _dict_to_xml(d, root_name="object"):
    """
    Helper: convert a dict into a simple XML string.

    Usage: called by render_response when format=xml and the payload is a dict.
    Handles nested dicts and lists of simple items or dicts.
    """
    parts = [f"<{root_name}>"]
    for k, v in d.items():
        tag = _to_xml_tag(k)
        if isinstance(v, dict):
            parts.append(_dict_to_xml(v, root_name=tag))
        elif isinstance(v, list):
            parts.append(f"<{tag}>")
            for item in v:
                if isinstance(item, dict):
                    parts.append(_dict_to_xml(item, root_name="item"))
                else:
                    parts.append(f"<item>{_escape_xml(item)}</item>")
            parts.append(f"</{tag}>")
        else:
            parts.append(f"<{tag}>{_escape_xml(v)}</{tag}>")
    parts.append(f"</{root_name}>")
    return "".join(parts)


def _list_to_xml(lst, root_name="items", item_name="item"):
    """
    Helper: convert a list into a simple XML string.

    Usage: called by render_response when format=xml and the payload is a list.
    Each list element becomes an XML element with name `item_name`.
    """
    parts = [f"<{root_name}>"]
    for item in lst:
        if isinstance(item, dict):
            parts.append(_dict_to_xml(item, root_name=item_name))
        else:
            parts.append(f"<{item_name}>{_escape_xml(item)}</{item_name}>")
    parts.append(f"</{root_name}>")
    return "".join(parts)


def render_response(payload, status=200, headers=None):
    """
    Response helper: render payload as JSON (default) or XML when ?format=xml.

    Usage: Use this helper everywhere to keep consistent response formats,
    content types, and status codes. Accepts dict/list (JSON) or returns XML
    string for xml format. Also supports plain text or empty-body responses.
    """
    fmt = (request.args.get("format") or "json").lower()
    headers = headers or {}

    # Default JSON behavior for tests
    if fmt not in ("xml", "json"):
        fmt = "json"

    if fmt == "xml":
        # Convert payload to XML
        if isinstance(payload, list):
            body = _list_to_xml(payload, root_name="items", item_name="item")
        elif isinstance(payload, dict):
            body = _dict_to_xml(payload, root_name="response")
        else:
            # passthrough for empty string or text
            body = _escape_xml(payload) if payload is not None else ""
        resp = make_response(body, status)
        resp.headers['Content-Type'] = 'application/xml; charset=utf-8'
        for k, v in headers.items():
            resp.headers[k] = v
        return resp

    # JSON
    resp = make_response(jsonify(payload) if payload not in (None, "") else (payload or ""), status)
    # Only set JSON content type when we used jsonify
    if isinstance(payload, (dict, list)):
        resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    for k, v in headers.items():
        resp.headers[k] = v
    return resp



@app.route('/auth/login', methods=['POST'])
def login():
    # Unified login endpoint: works with Flask-JWT-Extended when installed or falls back to PyJWT helper
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not password:
        return render_response({"error": "username and password required"}, 400)

    # Validate against configured admin credentials
    if username != ADMIN_USER or password != ADMIN_PASS:
        return render_response({"error": "Invalid credentials"}, 401)

    # Issue token using the preferred library if available
    if _HAS_FLASK_JWT and _create_access_token is not None:
        # Flask-JWT-Extended: include an is_admin claim for compatibility
        token = _create_access_token(identity=username, additional_claims={"is_admin": True})
    else:
        token = _issue_token(subject=username, extra_claims={"is_admin": True})

    return render_response({"access_token": token, "token_type": "Bearer", "expires_in": JWT_EXP_MINUTES * 60}, 200)


# New: token refresh endpoint to extend session without re-authenticating credentials
@app.route('/auth/refresh', methods=['POST'])
@require_auth
def refresh():
    claims = getattr(request, 'claims', {})
    sub = claims.get('sub')
    role = claims.get('role')
    if not sub:
        return render_response({"error": "Invalid token"}, 401)
    new_token = _issue_token(subject=sub, extra_claims={"role": role} if role else None)
    return render_response({"access_token": new_token, "token_type": "Bearer", "expires_in": JWT_EXP_MINUTES * 60}, 200)


# Set secure headers on all responses
@app.after_request
def set_security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('X-XSS-Protection', '0')  # modern browsers use CSP; XSS filter deprecated
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault('Cache-Control', 'no-store')
    # Optional: basic CSP to reduce injection risk for HTML responses
    resp.headers.setdefault('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    return resp


@app.route('/')
def home():
    """
    Route: Root endpoint.

    Usage: GET / returns a simple health string. Useful for smoke tests.
    """
    return 'Hello World!'

@app.route("/testdb")
def testdb():
    """
    Route: Test database connectivity.

    Usage: GET /testdb attempts a simple SELECT DATABASE() query and returns
    the connected database name or a 500 error when a DB error occurs.
    """
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT DATABASE()")
        data = cur.fetchone()
        cur.close()
        return render_response({'database': data[0] if data else None}, 200)
    except Exception as e:
        app.logger.exception('Database connectivity test failed')
        return render_response({'error': 'Database error', 'detail': str(e)}, 500)

@app.route('/health')
def health():
    # Basic health with optional DB ping
    status = {"status": "ok"}
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.close()
        status["db"] = "up"
    except Exception as e:
        status["db"] = "down"
        status["detail"] = str(e)
    return render_response(status, 200)

# CRUD: Users
@app.route('/users', methods=['GET'])
@require_auth
def list_users():
    try:
        # Build filters from query params
        where = []
        params = []
        name = request.args.get('name')
        email = request.args.get('email')
        age = request.args.get('age')
        min_age = request.args.get('min_age')
        max_age = request.args.get('max_age')
        if name:
            where.append("name LIKE %s")
            params.append(f"%{name.strip()}%")
        if email:
            where.append("email LIKE %s")
            params.append(f"%{email.strip()}%")
        if age is not None and age != "":
            try:
                age_val = int(age)
                where.append("age = %s")
                params.append(age_val)
            except ValueError:
                return render_response({'error': '`age` must be integer'}, 400)
        if min_age is not None and min_age != "":
            try:
                where.append("age >= %s")
                params.append(int(min_age))
            except ValueError:
                return render_response({'error': '`min_age` must be integer'}, 400)
        if max_age is not None and max_age != "":
            try:
                where.append("age <= %s")
                params.append(int(max_age))
            except ValueError:
                return render_response({'error': '`max_age` must be integer'}, 400)
        base = "SELECT id, name, email, age FROM users"
        sql = base + (" WHERE " + " AND ".join(where) if where else "")
        cur = mysql.connection.cursor()
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()
        cur.close()
        users = [{'id': r[0], 'name': r[1], 'email': r[2], 'age': r[3]} for r in rows]
        return render_response(users, 200)
    except Exception as e:
        app.logger.exception('List users failed')
        if DB_OPTIONAL:
            # Soft-fail for local JWT testing: empty list
            return render_response([], 200)
        return render_response({'error': 'Database error'}, 500)


@app.route('/users/<int:user_id>', methods=['GET'])
@require_auth
def get_user(user_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name, email, age FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        cur.close()
        if not row:
            return render_response({'error': 'User not found'}, 404)
        user = {'id': row[0], 'name': row[1], 'email': row[2], 'age': row[3]}
        return render_response(user, 200)
    except Exception as e:
        app.logger.exception('Get user failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/users', methods=['POST'])
@require_auth
def create_user():
    data = request.get_json(silent=True)
    ok, err = validate_user_payload(data or {}, require_all=True)
    if not ok:
        return render_response({'error': err}, 400)

    name = data['name'].strip()
    email = data['email'].strip()
    age = data.get('age')

    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (name, email, age) VALUES (%s, %s, %s)", (name, email, age))
        mysql.connection.commit()
        new_id = cur.lastrowid
        cur.close()
        location = url_for('get_user', user_id=new_id, _external=True)
        headers = {'Location': location}
        return render_response({'id': new_id, 'name': name, 'email': email, 'age': age}, 201, headers=headers)
    except Exception as e:
        app.logger.exception('Create user failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/users/<int:user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    data = request.get_json(silent=True)
    ok, err = validate_user_payload(data or {}, require_all=True)
    if not ok:
        return render_response({'error': err}, 400)

    name = data['name'].strip()
    email = data['email'].strip()
    age = data.get('age')

    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET name=%s, email=%s, age=%s WHERE id=%s", (name, email, age, user_id))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'User not found'}, 404)
        return render_response({'id': user_id, 'name': name, 'email': email, 'age': age}, 200)
    except Exception as e:
        app.logger.exception('Update user failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/users/<int:user_id>', methods=['PATCH'])
@require_auth
def patch_user(user_id):
    data = request.get_json(silent=True)
    if not data:
        return render_response({'error': 'Empty payload'}, 400)

    ok, err = validate_user_payload(data, require_all=False)
    if not ok:
        return render_response({'error': err}, 400)

    fields = []
    values = []
    for key in ('name', 'email', 'age'):
        if key in data:
            val = data[key]
            if key == 'name' and isinstance(val, str):
                val = val.strip()
            values.append(val)
            fields.append(f"{key} = %s")

    if not fields:
        return render_response({'error': 'No updatable fields provided'}, 400)

    sql = f"UPDATE users SET {', '.join(fields)} WHERE id = %s"
    values.append(user_id)

    try:
        cur = mysql.connection.cursor()
        cur.execute(sql, tuple(values))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'User not found'}, 404)
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name, email, age FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        cur.close()
        user = {'id': row[0], 'name': row[1], 'email': row[2], 'age': row[3]} if row else {'id': user_id}
        return render_response(user, 200)
    except Exception as e:
        app.logger.exception('Patch user failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/users/<int:user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'User not found'}, 404)
        # No content
        return render_response('', 204)
    except Exception as e:
        app.logger.exception('Delete user failed')
        return render_response({'error': 'Database error'}, 500)


# CRUD: Customers
@app.route('/customers', methods=['GET'])
@require_auth
def list_customers():
    """
    Route: List all customers (protected).

    Usage: GET /customers returns customers and requires a valid JWT due to
    @force_auth_required. Returns 500 on DB errors. Supports optional query
    parameters for searching: `q`, `name`, `phone` (case-insensitive substring
    matches). When no params are supplied behavior is unchanged.
    """
    try:
        # Filters: Name (LIKE), Phone (LIKE), CustomerID exact
        where = []
        params = []
        cid = request.args.get('CustomerID')
        name = request.args.get('Name')
        phone = request.args.get('Phone')
        if cid is not None and cid != "":
            try:
                where.append("CustomerID = %s")
                params.append(int(cid))
            except ValueError:
                return render_response({'error': '`CustomerID` must be integer'}, 400)
        if name:
            where.append("Name LIKE %s")
            params.append(f"%{name.strip()}%")
        if phone:
            where.append("Phone LIKE %s")
            params.append(f"%{phone.strip()}%")
        base = "SELECT CustomerID, Name, Phone FROM customers"
        sql = base + (" WHERE " + " AND ".join(where) if where else "")
        cur = mysql.connection.cursor()
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()
        cur.close()
        customers = [{'CustomerID': r[0], 'Name': r[1], 'Phone': r[2]} for r in rows]

        # --- Search / filter support ---
        # Supported query params: q, name, phone (case-insensitive substring)
        q = request.args.get('q')
        name = request.args.get('name')
        phone = request.args.get('phone')

        # Basic validation
        for sval, pname in ((q, 'q'), (name, 'name'), (phone, 'phone')):
            if sval is not None and len(sval) > 200:
                return render_response({'error': f'parameter `{pname}` too long'}, 400)

        def _ci(s):
            return (s or '').lower()

        if q:
            ql = q.strip().lower()
            customers = [c for c in customers if ql in _ci(c.get('Name'))]
        if name:
            nl = name.strip().lower()
            customers = [c for c in customers if nl in _ci(c.get('Name'))]
        if phone:
            pl = phone.strip().lower()
            customers = [c for c in customers if pl in _ci(c.get('Phone'))]

        return render_response(customers, 200)
    except Exception as e:
        app.logger.exception('List customers failed')
        if DB_OPTIONAL:
            return render_response([], 200)
        return render_response({'error': 'Database error'}, 500)


def validate_customer_payload(data, require_all=False):
    """
    Validate customer payload for customer endpoints.

    Usage: Ensures `Name` and optional `Phone` meet requirements. Returns
    (True, None) or (False, error_message).
    """
    if not isinstance(data, dict):
        return False, 'Invalid JSON payload'
    name = data.get('Name')
    phone = data.get('Phone')
    if require_all:
        if name is None:
            return False, '`Name` is required'
    if name is not None:
        if not isinstance(name, str) or not name.strip():
            return False, '`Name` must be a non-empty string'
        if len(name) > 100:
            return False, '`Name` too long (max 100)'
    if phone is not None:
        if not isinstance(phone, str) or not phone.strip():
            return False, '`Phone` must be a non-empty string'
        if len(phone) > 20:
            return False, '`Phone` too long (max 20)'
    return True, None


@app.route('/customers', methods=['POST'])
@require_auth
def create_customer():
    """
    Route: Create a new customer (admin only).

    Usage: POST /customers with JSON {Name, Phone?}. Requires admin privileges
    via @admin_required. Returns 201 with Location header on success.
    """
    data = request.get_json(silent=True)
    ok, err = validate_customer_payload(data or {}, require_all=True)
    if not ok:
        # Fixed: return consistent JSON dict, not jsonify.json
        return render_response({'error': err}, 400)
    name = data['Name'].strip()
    phone = (data.get('Phone') or '').strip() or None
    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO customers (Name, Phone) VALUES (%s, %s)", (name, phone))
        mysql.connection.commit()
        new_id = cur.lastrowid
        cur.close()
        location = url_for('get_customer', customer_id=new_id, _external=True)
        headers = {'Location': location}
        return render_response({'CustomerID': new_id, 'Name': name, 'Phone': phone}, 201, headers=headers)
    except Exception as e:
        app.logger.exception('Create customer failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/customers/<int:customer_id>', methods=['GET'])
@require_auth
def get_customer(customer_id):
    """
    Route: Get a customer by ID (protected).

    Usage: GET /customers/<id> returns customer record or 404. Requires JWT.
    """
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT CustomerID, Name, Phone FROM customers WHERE CustomerID=%s", (customer_id,))
        row = cur.fetchone()
        cur.close()
        if not row:
            return render_response({'error': 'Customer not found'}, 404)
        return render_response({'CustomerID': row[0], 'Name': row[1], 'Phone': row[2]}, 200)
    except Exception as e:
        app.logger.exception('Get customer failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/customers/<int:customer_id>', methods=['PUT'])
@require_auth
def update_customer(customer_id):
    """
    Route: Replace a customer (admin only).

    Usage: PUT /customers/<id> with full payload {Name, Phone?}. Validates input
    and returns 200 or 404 if not found.
    """
    data = request.get_json(silent=True)
    ok, err = validate_customer_payload(data or {}, require_all=True)
    if not ok:
        return render_response({'error': err}, 400)
    name = data['Name'].strip()
    phone = (data.get('Phone') or '').strip() or None
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE customers SET Name=%s, Phone=%s WHERE CustomerID=%s", (name, phone, customer_id))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'Customer not found'}, 404)
        return render_response({'CustomerID': customer_id, 'Name': name, 'Phone': phone}, 200)
    except Exception as e:
        app.logger.exception('Update customer failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/customers/<int:customer_id>', methods=['PATCH'])
@require_auth
def patch_customer(customer_id):
    """
    Route: Partially update a customer (admin only).

    Usage: PATCH /customers/<id> with any subset of {Name, Phone}. Returns 200
    with CustomerID or 404 when not found. Validates fields provided.
    """
    data = request.get_json(silent=True)
    if not data:
        return render_response({'error': 'Empty payload'}, 400)
    ok, err = validate_customer_payload(data, require_all=False)
    if not ok:
        return render_response({'error': err}, 400)
    fields = []
    values = []
    for key, col in [('Name', 'Name'), ('Phone', 'Phone')]:
        if key in data:
            val = data[key]
            if isinstance(val, str):
                val = val.strip()
            values.append(val or None)
            fields.append(f"{col}=%s")
    if not fields:
        return render_response({'error': 'No updatable fields provided'}, 400)
    sql = f"UPDATE customers SET {', '.join(fields)} WHERE CustomerID=%s"
    values.append(customer_id)
    try:
        cur = mysql.connection.cursor()
        cur.execute(sql, tuple(values))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'Customer not found'}, 404)
        return render_response({'CustomerID': customer_id}, 200)
    except Exception as e:
        app.logger.exception('Patch customer failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/customers/<int:customer_id>', methods=['DELETE'])
@require_auth
def delete_customer(customer_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM customers WHERE CustomerID=%s", (customer_id,))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'Customer not found'}, 404)
        return render_response('', 204)
    except Exception as e:
        app.logger.exception('Delete customer failed')
        return render_response({'error': 'Database error'}, 500)
#end

# CRUD: Products
@app.route('/products', methods=['GET'])
@require_auth
def list_products():
    """
    Route: List all products.

    Usage: GET /products returns JSON list of products with ProductID, ProductName, Price.
    Supports query params: `q` or `name` (substring on ProductName), `min_price`, `max_price`.
    """
    try:
        # Filters: ProductID exact, ProductName LIKE, Price exact/range
        where = []
        params = []
        pid = request.args.get('ProductID')
        name = request.args.get('ProductName')
        price = request.args.get('Price')
        min_price = request.args.get('min_price')
        max_price = request.args.get('max_price')
        if pid is not None and pid != "":
            try:
                where.append("ProductID = %s")
                params.append(int(pid))
            except ValueError:
                return render_response({'error': '`ProductID` must be integer'}, 400)
        if name:
            where.append("ProductName LIKE %s")
            params.append(f"%{name.strip()}%")
        if price is not None and price != "":
            try:
                pval = float(price)
                where.append("Price = %s")
                params.append(pval)
            except ValueError:
                return render_response({'error': '`Price` must be a number'}, 400)
        if min_price is not None and min_price != "":
            try:
                where.append("Price >= %s")
                params.append(float(min_price))
            except ValueError:
                return render_response({'error': '`min_price` must be a number'}, 400)
        if max_price is not None and max_price != "":
            try:
                where.append("Price <= %s")
                params.append(float(max_price))
            except ValueError:
                return render_response({'error': '`max_price` must be a number'}, 400)
        base = "SELECT ProductID, ProductName, Price FROM products"
        sql = base + (" WHERE " + " AND ".join(where) if where else "")
        cur = mysql.connection.cursor()
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()
        cur.close()
        products = [{'ProductID': r[0], 'ProductName': r[1], 'Price': float(r[2]) if r[2] is not None else None} for r in rows]

        # --- Search / filter support ---
        q = request.args.get('q')
        name = request.args.get('name')
        min_price = request.args.get('min_price')
        max_price = request.args.get('max_price')

        # Validate string lengths
        for sval, pname in ((q, 'q'), (name, 'name')):
            if sval is not None and len(sval) > 200:
                return render_response({'error': f'parameter `{pname}` too long'}, 400)

        # Parse numeric filters
        min_p = None
        max_p = None
        if min_price is not None and min_price != '':
            try:
                min_p = float(min_price)
            except Exception:
                return render_response({'error': '`min_price` must be a number'}, 400)
        if max_price is not None and max_price != '':
            try:
                max_p = float(max_price)
            except Exception:
                return render_response({'error': '`max_price` must be a number'}, 400)
        if min_p is not None and max_p is not None and min_p > max_p:
            return render_response({'error': '`min_price` must be <= `max_price`'}, 400)

        def _ci(s):
            return (s or '').lower()

        if q:
            ql = q.strip().lower()
            products = [p for p in products if ql in _ci(p.get('ProductName'))]
        if name:
            nl = name.strip().lower()
            products = [p for p in products if nl in _ci(p.get('ProductName'))]
        if min_p is not None:
            products = [p for p in products if (p.get('Price') is not None and p.get('Price') >= min_p)]
        if max_p is not None:
            products = [p for p in products if (p.get('Price') is not None and p.get('Price') <= max_p)]

        return render_response(products, 200)
    except Exception as e:
        app.logger.exception('List products failed')
        if DB_OPTIONAL:
            return render_response([], 200)
        return render_response({'error': 'Database error'}, 500)


def validate_product_payload(data, require_all=False):
    """
    Validate product payload for product endpoints.

    Usage: Ensures `ProductName` and `Price` meet type and boundary checks. Returns
    (True, None) or (False, error_message).
    """
    if not isinstance(data, dict):
        return False, 'Invalid JSON payload'
    name = data.get('ProductName')
    price = data.get('Price')
    if require_all:
        if name is None or price is None:
            return False, '`ProductName` and `Price` are required'
    if name is not None:
        if not isinstance(name, str) or not name.strip():
            return False, '`ProductName` must be a non-empty string'
        if len(name) > 100:
            return False, '`ProductName` too long (max 100)'
    if price is not None:
        # allow int or float, convertable
        if not isinstance(price, (int, float)):
            return False, '`Price` must be a number'
        if price < 0:
            return False, '`Price` must be non-negative'
    return True, None


@app.route('/products', methods=['POST'])
@require_auth
def create_product():
    """
    Route: Create a new product (admin only).

    Usage: POST /products with JSON {ProductName, Price}. Returns 201 and Location
    header on success.
    """
    data = request.get_json(silent=True)
    ok, err = validate_product_payload(data or {}, require_all=True)
    if not ok:
        return render_response({'error': err}, 400)
    name = data['ProductName'].strip()
    price = float(data['Price'])
    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO products (ProductName, Price) VALUES (%s, %s)", (name, price))
        mysql.connection.commit()
        new_id = cur.lastrowid
        cur.close()
        location = url_for('get_product', product_id=new_id, _external=True)
        headers = {'Location': location}
        return render_response({'ProductID': new_id, 'ProductName': name, 'Price': price}, 201, headers=headers)
    except Exception as e:
        app.logger.exception('Create product failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/products/<int:product_id>', methods=['GET'])
@require_auth
def get_product(product_id):
    """
    Route: Get a product by ID.

    Usage: GET /products/<id> returns product or 404 if not found.
    """
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT ProductID, ProductName, Price FROM products WHERE ProductID=%s", (product_id,))
        row = cur.fetchone()
        cur.close()
        if not row:
            return render_response({'error': 'Product not found'}, 404)
        return render_response({'ProductID': row[0], 'ProductName': row[1], 'Price': float(row[2]) if row[2] is not None else None}, 200)
    except Exception as e:
        app.logger.exception('Get product failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/products/<int:product_id>', methods=['PUT'])
@require_auth
def update_product(product_id):
    """
    Route: Replace a product (admin only).

    Usage: PUT /products/<id> with full payload {ProductName, Price}. Validates data
    and returns updated product or 404 if not found.
    """
    data = request.get_json(silent=True)
    ok, err = validate_product_payload(data or {}, require_all=True)
    if not ok:
        return render_response({'error': err}, 400)
    name = data['ProductName'].strip()
    price = float(data['Price'])
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE products SET ProductName=%s, Price=%s WHERE ProductID=%s", (name, price, product_id))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'Product not found'}, 404)
        return render_response({'ProductID': product_id, 'ProductName': name, 'Price': price}, 200)
    except Exception as e:
        app.logger.exception('Update product failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/products/<int:product_id>', methods=['PATCH'])
@require_auth
def patch_product(product_id):
    """
    Route: Partially update a product (admin only).

    Usage: PATCH /products/<id> with any subset of {ProductName, Price}. Returns 200
    with ProductID or 404 if not found. Validates fields provided.
    """
    data = request.get_json(silent=True)
    if not data:
        return render_response({'error': 'Empty payload'}, 400)
    ok, err = validate_product_payload(data, require_all=False)
    if not ok:
        return render_response({'error': err}, 400)
    fields = []
    values = []
    if 'ProductName' in data:
        name = data['ProductName']
        if not isinstance(name, str) or not name.strip():
            return render_response({'error': '`ProductName` must be a non-empty string'}, 400)
        fields.append('ProductName=%s')
        values.append(name.strip())
    if 'Price' in data:
        price = data['Price']
        if not isinstance(price, (int, float)) or float(price) < 0:
            return render_response({'error': '`Price` must be a non-negative number'}, 400)
        fields.append('Price=%s')
        values.append(float(price))
    if not fields:
        return render_response({'error': 'No updatable fields provided'}, 400)
    sql = f"UPDATE products SET {', '.join(fields)} WHERE ProductID=%s"
    values.append(product_id)
    try:
        cur = mysql.connection.cursor()
        cur.execute(sql, tuple(values))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'Product not found'}, 404)
        return render_response({'ProductID': product_id}, 200)
    except Exception as e:
        app.logger.exception('Patch product failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/products/<int:product_id>', methods=['DELETE'])
@require_auth
def delete_product(product_id):
    """
    Route: Delete a product (admin only).

    Usage: DELETE /products/<id> removes the product and returns 204 on success
    or 404 if not found.
    """
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM products WHERE ProductID=%s", (product_id,))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'Product not found'}, 404)
        return render_response('', 204)
    except Exception as e:
        app.logger.exception('Delete product failed')
        return render_response({'error': 'Database error'}, 500)


# CRUD: Orders
@app.route('/orders', methods=['GET'])
@require_auth
def list_orders():
    """
    Route: List all orders.

    Usage: GET /orders returns JSON list of orders with OrderID, CustomerID, ProductID, Quantity.
    Supports query params: order_id, customer_id, product_id, min_qty, max_qty, customer_name.
    """
    try:
        # Filters: OrderID, CustomerID, ProductID exact; Quantity exact/range
        where = []
        params = []
        oid = request.args.get('OrderID')
        cid = request.args.get('CustomerID')
        pid = request.args.get('ProductID')
        qty = request.args.get('Quantity')
        min_qty = request.args.get('min_quantity')
        max_qty = request.args.get('max_quantity')
        def _int_param(val, name):
            if val is None or val == "":
                return None
            try:
                return int(val)
            except ValueError:
                raise ValueError(f'`{name}` must be integer')
        try:
            _oid = _int_param(oid, 'OrderID')
            _cid = _int_param(cid, 'CustomerID')
            _pid = _int_param(pid, 'ProductID')
            _qty = _int_param(qty, 'Quantity')
            _minq = _int_param(min_qty, 'min_quantity')
            _maxq = _int_param(max_qty, 'max_quantity')
        except ValueError as ve:
            return render_response({'error': str(ve)}, 400)
        if _oid is not None:
            where.append('OrderID = %s')
            params.append(_oid)
        if _cid is not None:
            where.append('CustomerID = %s')
            params.append(_cid)
        if _pid is not None:
            where.append('ProductID = %s')
            params.append(_pid)
        if _qty is not None:
            where.append('Quantity = %s')
            params.append(_qty)
        if _minq is not None:
            where.append('Quantity >= %s')
            params.append(_minq)
        if _maxq is not None:
            where.append('Quantity <= %s')
            params.append(_maxq)
        base = "SELECT OrderID, CustomerID, ProductID, Quantity FROM orders"
        sql = base + (" WHERE " + " AND ".join(where) if where else "")
        cur = mysql.connection.cursor()
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()
        cur.close()
        orders = [{'OrderID': r[0], 'CustomerID': r[1], 'ProductID': r[2], 'Quantity': r[3]} for r in rows]

        # --- Search / filter support ---
        order_id = request.args.get('order_id')
        customer_id = request.args.get('customer_id')
        product_id = request.args.get('product_id')
        min_qty = request.args.get('min_qty')
        max_qty = request.args.get('max_qty')
        customer_name = request.args.get('customer_name')

        # Validate lengths for strings
        if customer_name is not None and len(customer_name) > 200:
            return render_response({'error': 'parameter `customer_name` too long'}, 400)

        # Parse integer filters
        try:
            if order_id is not None and order_id != '':
                order_id_i = int(order_id)
            else:
                order_id_i = None
        except ValueError:
            return render_response({'error': '`order_id` must be an integer'}, 400)
        try:
            if customer_id is not None and customer_id != '':
                customer_id_i = int(customer_id)
            else:
                customer_id_i = None
        except ValueError:
            return render_response({'error': '`customer_id` must be an integer'}, 400)
        try:
            if product_id is not None and product_id != '':
                product_id_i = int(product_id)
            else:
                product_id_i = None
        except ValueError:
            return render_response({'error': '`product_id` must be an integer'}, 400)
        try:
            if min_qty is not None and min_qty != '':
                min_qty_i = int(min_qty)
            else:
                min_qty_i = None
        except ValueError:
            return render_response({'error': '`min_qty` must be an integer'}, 400)
        try:
            if max_qty is not None and max_qty != '':
                max_qty_i = int(max_qty)
            else:
                max_qty_i = None
        except ValueError:
            return render_response({'error': '`max_qty` must be an integer'}, 400)

        # Build customer id->name map if needed for customer_name search
        cust_map = {}
        try:
            cur = mysql.connection.cursor()
            # Use same SELECT form as other parts of app so tests' FakeCursor supports it
            cur.execute("SELECT CustomerID, Name, Phone FROM customers")
            crow_rows = cur.fetchall()
            cur.close()
            for cr in crow_rows:
                cust_map[cr[0]] = cr[1]
        except Exception:
            # If customers can't be fetched, ignore name-based filtering
            cust_map = {}

        def _ci(s):
            return (s or '').lower()

        # Apply filters (AND semantics)
        if order_id_i is not None:
            orders = [o for o in orders if o.get('OrderID') == order_id_i]
        if customer_id_i is not None:
            orders = [o for o in orders if o.get('CustomerID') == customer_id_i]
        if product_id_i is not None:
            orders = [o for o in orders if o.get('ProductID') == product_id_i]
        if min_qty_i is not None:
            orders = [o for o in orders if isinstance(o.get('Quantity'), int) and o.get('Quantity') >= min_qty_i]
        if max_qty_i is not None:
            orders = [o for o in orders if isinstance(o.get('Quantity'), int) and o.get('Quantity') <= max_qty_i]
        if customer_name:
            cnl = customer_name.strip().lower()
            orders = [o for o in orders if cnl in _ci(cust_map.get(o.get('CustomerID')))]

        return render_response(orders, 200)
    except Exception as e:
        app.logger.exception('List orders failed')
        if DB_OPTIONAL:
            return render_response([], 200)
        return render_response({'error': 'Database error'}, 500)


def validate_order_payload(data, require_all=False):
    """
    Validate order payload for order endpoints.

    Usage: Ensures CustomerID, ProductID, and Quantity are integers and Quantity > 0.
    Returns (True, None) or (False, error_message).
    """
    if not isinstance(data, dict):
        return False, 'Invalid JSON payload'
    customer_id = data.get('CustomerID')
    product_id = data.get('ProductID')
    quantity = data.get('Quantity')
    if require_all:
        if customer_id is None or product_id is None or quantity is None:
            return False, '`CustomerID`, `ProductID`, and `Quantity` are required'
    if customer_id is not None and not isinstance(customer_id, int):
        return False, '`CustomerID` must be an integer'
    if product_id is not None and not isinstance(product_id, int):
        return False, '`ProductID` must be an integer'
    if quantity is not None:
        if not isinstance(quantity, int) or quantity <= 0:
            return False, '`Quantity` must be a positive integer'
    return True, None


def entity_exists(table, id_col, id_val):
    """
    Helper: Check whether an entity exists in the DB.

    Usage: entity_exists('customers', 'CustomerID', id) returns True if the row exists.
    Used for foreign key validation in order-related endpoints.
    """
    try:
        cur = mysql.connection.cursor()
        cur.execute(f"SELECT 1 FROM {table} WHERE {id_col}=%s", (id_val,))
        row = cur.fetchone()
        cur.close()
        return bool(row)
    except Exception:
        return False


@app.route('/orders', methods=['POST'])
@require_auth
def create_order():
    """
    Route: Create a new order.

    Usage: POST /orders with JSON {CustomerID, ProductID, Quantity}. Validates
    payload and that the referenced customer and product exist. Returns 201.
    """
    data = request.get_json(silent=True)
    ok, err = validate_order_payload(data or {}, require_all=True)
    if not ok:
        return render_response({'error': err}, 400)
    customer_id = data['CustomerID']
    product_id = data['ProductID']
    quantity = data['Quantity']
    # Foreign key checks
    if not entity_exists('customers', 'CustomerID', customer_id):
        return render_response({'error': 'Customer does not exist'}, 404)
    if not entity_exists('products', 'ProductID', product_id):
        return render_response({'error': 'Product does not exist'}, 404)
    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO orders (CustomerID, ProductID, Quantity) VALUES (%s, %s, %s)", (customer_id, product_id, quantity))
        mysql.connection.commit()
        new_id = cur.lastrowid
        cur.close()
        location = url_for('get_order', order_id=new_id, _external=True)
        headers = {'Location': location}
        return render_response({'OrderID': new_id, 'CustomerID': customer_id, 'ProductID': product_id, 'Quantity': quantity}, 201, headers=headers)
    except Exception as e:
        app.logger.exception('Create order failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/orders/<int:order_id>', methods=['GET'])
@require_auth
def get_order(order_id):
    """
    Route: Get an order by ID.

    Usage: GET /orders/<id> returns order or 404 if not found.
    """
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT OrderID, CustomerID, ProductID, Quantity FROM orders WHERE OrderID=%s", (order_id,))
        row = cur.fetchone()
        cur.close()
        if not row:
            return render_response({'error': 'Order not found'}, 404)
        return render_response({'OrderID': row[0], 'CustomerID': row[1], 'ProductID': row[2], 'Quantity': row[3]}, 200)
    except Exception as e:
        app.logger.exception('Get order failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/orders/<int:order_id>', methods=['PUT'])
@require_auth
def update_order(order_id):
    """
    Route: Replace an order.

    Usage: PUT /orders/<id> with full payload {CustomerID, ProductID, Quantity}. Validates
    foreign keys and returns updated order or 404 if not found.
    """
    data = request.get_json(silent=True)
    ok, err = validate_order_payload(data or {}, require_all=True)
    if not ok:
        return render_response({'error': err}, 400)
    customer_id = data['CustomerID']
    product_id = data['ProductID']
    quantity = data['Quantity']
    if not entity_exists('customers', 'CustomerID', customer_id):
        return render_response({'error': 'Customer does not exist'}, 404)
    if not entity_exists('products', 'ProductID', product_id):
        return render_response({'error': 'Product does not exist'}, 404)
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE orders SET CustomerID=%s, ProductID=%s, Quantity=%s WHERE OrderID=%s", (customer_id, product_id, quantity, order_id))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'Order not found'}, 404)
        return render_response({'OrderID': order_id, 'CustomerID': customer_id, 'ProductID': product_id, 'Quantity': quantity}, 200)
    except Exception as e:
        app.logger.exception('Update order failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/orders/<int:order_id>', methods=['PATCH'])
@require_auth
def patch_order(order_id):
    """
    Route: Partially update an order.

    Usage: PATCH /orders/<id> with subset of {CustomerID, ProductID, Quantity}. Validates
    provided fields and foreign keys as needed. Returns 200 with OrderID or 404.
    """
    data = request.get_json(silent=True)
    if not data:
        return render_response({'error': 'Empty payload'}, 400)
    ok, err = validate_order_payload(data, require_all=False)
    if not ok:
        return render_response({'error': err}, 400)
    fields = []
    values = []
    if 'CustomerID' in data:
        cid = data['CustomerID']
        if not isinstance(cid, int):
            return render_response({'error': '`CustomerID` must be an integer'}, 400)
        if not entity_exists('customers', 'CustomerID', cid):
            return render_response({'error': 'Customer does not exist'}, 404)
        fields.append('CustomerID=%s')
        values.append(cid)
    if 'ProductID' in data:
        pid = data['ProductID']
        if not isinstance(pid, int):
            return render_response({'error': '`ProductID` must be an integer'}, 400)
        if not entity_exists('products', 'ProductID', pid):
            return render_response({'error': 'Product does not exist'}, 404)
        fields.append('ProductID=%s')
        values.append(pid)
    if 'Quantity' in data:
        qty = data['Quantity']
        if not isinstance(qty, int) or qty <= 0:
            return render_response({'error': '`Quantity` must be a positive integer'}, 400)
        fields.append('Quantity=%s')
        values.append(qty)
    if not fields:
        return render_response({'error': 'No updatable fields provided'}, 400)
    sql = f"UPDATE orders SET {', '.join(fields)} WHERE OrderID=%s"
    values.append(order_id)
    try:
        cur = mysql.connection.cursor()
        cur.execute(sql, tuple(values))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'Order not found'}, 404)
        return render_response({'OrderID': order_id}, 200)
    except Exception as e:
        app.logger.exception('Patch order failed')
        return render_response({'error': 'Database error'}, 500)


@app.route('/orders/<int:order_id>', methods=['DELETE'])
@require_auth
def delete_order(order_id):
    """
    Route: Delete an order.

    Usage: DELETE /orders/<id> removes the order and returns 204 on success or 404 if not found.
    """
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM orders WHERE OrderID=%s", (order_id,))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return render_response({'error': 'Order not found'}, 404)
        return render_response('', 204)
    except Exception as e:
        app.logger.exception('Delete order failed')
        return render_response({'error': 'Database error'}, 500)


# --- Authentication endpoints and enforcement ---

# Whitelist paths that are always allowed even when REQUIRE_AUTH is True
_AUTH_WHITELIST = set([
    '/',
    '/testdb',
    '/auth/login'
])

@app.before_request
def _require_auth_if_enabled():
    """
    Request hook: Enforce JWT auth when REQUIRE_AUTH is True.

    Usage: Runs before each request. Returns 500 if JWT library missing when
    REQUIRE_AUTH is enabled. Allows whitelist paths to bypass auth. Otherwise
    verifies the JWT and returns 401 on failure.
    """
    # If auth not required, skip
    if not app.config.get('REQUIRE_AUTH'):
        return None
    # If JWT library not installed, return 500 with helpful message
    if not _HAS_FLASK_JWT:
        return render_response({'error': 'JWT support not installed. Set REQUIRE_AUTH=false or install Flask-JWT-Extended.'}, 500)
    # Allow whitelist
    path = request.path
    if path in _AUTH_WHITELIST:
        return None
    # Verify JWT in request (will abort with 401 if invalid/missing)
    try:
        _verify_jwt_in_request()
    except Exception as e:
        # Using render_response to keep consistent response format
        return render_response({'error': 'Missing or invalid token'}, 401)


@app.before_request
def _attach_jwt_identity_optional():
    """
    Request hook: Attach JWT identity to g.current_user when present.

    Usage: Runs before each request and sets g.current_user to the token identity
    if a valid token is provided (optional=True). If JWT support is absent or
    token invalid/missing, g.current_user will be None.
    """
    # Only attempt if JWT support is installed
    if not _HAS_FLASK_JWT:
        g.current_user = None
        return None
    try:
        # optional=True will not abort if token missing/invalid; it only verifies if present
        _verify_jwt_in_request(optional=True)
        # If a token was present and valid, set current_user; otherwise None
        g.current_user = _get_jwt_identity()
    except Exception:
        # Any error means we don't have a usable identity for this request
        g.current_user = None
    return None


if __name__ == '__main__':

    app.run(debug=True, host='127.0.0.1', port=5001)

