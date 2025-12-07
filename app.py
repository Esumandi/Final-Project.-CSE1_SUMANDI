from flask import Flask, jsonify, request, url_for, make_response
from flask_mysqldb import MySQL
import re

app = Flask(__name__)

app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Pentagon0211'
app.config['MYSQL_DB'] = 'CS_ELECT'

mysql = MySQL(app)

# Validation helpers
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --- Response formatting helper ---

def _to_xml_tag(key):
    # Ensure valid XML tag by removing spaces and non-alnum (basic safety)
    safe = re.sub(r"[^a-zA-Z0-9_]", "", str(key)) or "item"
    # Tags cannot start with a digit
    if safe[0].isdigit():
        safe = f"_{safe}"
    return safe


def _escape_xml(text):
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
    parts = [f"<{root_name}>"]
    for item in lst:
        if isinstance(item, dict):
            parts.append(_dict_to_xml(item, root_name=item_name))
        else:
            parts.append(f"<{item_name}>{_escape_xml(item)}</{item_name}>")
    parts.append(f"</{root_name}>")
    return "".join(parts)


def render_response(payload, status=200, headers=None):
    """Render payload as JSON (default) or XML based on `format` query arg.
    - Accepts dict or list payload. For non-JSON payload (string/None), returns as-is.
    - Sets appropriate Content-Type header.
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


def validate_user_payload(data, require_all=False):
    if not isinstance(data, dict):
        return False, "Invalid JSON payload"
    name = data.get('name')
    email = data.get('email')
    age = data.get('age', None)

    if require_all:
        if name is None or email is None:
            return False, "`name` and `email` are required"

    if name is not None:
        if not isinstance(name, str) or not name.strip():
            return False, "`name` must be a non-empty string"
        if len(name) > 100:
            return False, "`name` too long (max 100)"

    if email is not None:
        if not isinstance(email, str) or not EMAIL_RE.match(email):
            return False, "`email` is invalid"
        if len(email) > 100:
            return False, "`email` too long (max 100)"

    if age is not None:
        if not (isinstance(age, int) and 0 <= age <= 150):
            return False, "`age` must be integer between 0 and 150"

    return True, None


@app.route('/')
def home():
    return 'Hello World!'

@app.route("/testdb")
def testdb():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT DATABASE()")
        data = cur.fetchone()
        cur.close()
        return render_response({'database': data[0] if data else None}, 200)
    except Exception as e:
        app.logger.exception('Database connectivity test failed')
        return render_response({'error': 'Database error', 'detail': str(e)}, 500)

# CRUD: Users
@app.route('/users', methods=['GET'])
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
        return render_response({'error': 'Database error'}, 500)


@app.route('/users/<int:user_id>', methods=['GET'])
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
def list_customers():
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
        return render_response(customers, 200)
    except Exception as e:
        app.logger.exception('List customers failed')
        return render_response({'error': 'Database error'}, 500)


def validate_customer_payload(data, require_all=False):
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
def create_customer():
    data = request.get_json(silent=True)
    ok, err = validate_customer_payload(data or {}, require_all=True)
    if not ok:
        return render_response(jsonify({'error': err}).json, 400)
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
def get_customer(customer_id):
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
def update_customer(customer_id):
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
def patch_customer(customer_id):
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


# CRUD: Products
@app.route('/products', methods=['GET'])
def list_products():
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
        return render_response(products, 200)
    except Exception as e:
        app.logger.exception('List products failed')
        return render_response({'error': 'Database error'}, 500)


def validate_product_payload(data, require_all=False):
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
def create_product():
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
def get_product(product_id):
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
def update_product(product_id):
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
def patch_product(product_id):
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
def delete_product(product_id):
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
def list_orders():
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
        return render_response(orders, 200)
    except Exception as e:
        app.logger.exception('List orders failed')
        return render_response({'error': 'Database error'}, 500)


def validate_order_payload(data, require_all=False):
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
    try:
        cur = mysql.connection.cursor()
        cur.execute(f"SELECT 1 FROM {table} WHERE {id_col}=%s", (id_val,))
        row = cur.fetchone()
        cur.close()
        return bool(row)
    except Exception:
        return False


@app.route('/orders', methods=['POST'])
def create_order():
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
def get_order(order_id):
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
def update_order(order_id):
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
def patch_order(order_id):
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
def delete_order(order_id):
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


if __name__ == '__main__':
    # Bind to localhost on a non-conflicting port to avoid AirPlay/AirTunes intercepting 5000
    app.run(debug=True, host='127.0.0.1', port=5001)
