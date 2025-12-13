import pytest

# Minimal fake DB to simulate MySQL operations used by the app
class FakeCursor:
    def __init__(self, db):
        self.db = db
        self._result = None
        self.lastrowid = None
        self.rowcount = 0

    def execute(self, sql, params=None):
        params = params or tuple()
        sql = sql.strip()
        # Customers
        if sql.startswith("SELECT CustomerID, Name, Phone FROM customers WHERE CustomerID="):
            cid = params[0]
            row = self.db['customers'].get(cid)
            self._result = (cid, row['Name'], row.get('Phone')) if row else None
        elif sql == "SELECT CustomerID, Name, Phone FROM customers":
            rows = []
            for cid, row in sorted(self.db['customers'].items()):
                rows.append((cid, row['Name'], row.get('Phone')))
            self._result = rows
        elif sql.startswith("INSERT INTO customers (Name, Phone) VALUES"):
            name, phone = params
            cid = self.db['seq']['customers']
            self.db['seq']['customers'] += 1
            self.db['customers'][cid] = {'Name': name, 'Phone': phone}
            self.lastrowid = cid
            self.rowcount = 1
        elif sql.startswith("UPDATE customers SET") and "WHERE CustomerID=" in sql:
            # Handles both PUT and PATCH
            *values, cid = params
            if cid in self.db['customers']:
                cust = self.db['customers'][cid]
                cols = []
                if 'Name=' in sql:
                    cust['Name'] = values[0]
                    cols.append('Name')
                if 'Phone=' in sql:
                    # Phone may be in first or second position depending on presence of Name
                    idx = 1 if 'Name=' in sql else 0
                    cust['Phone'] = values[idx]
                    cols.append('Phone')
                self.rowcount = 1
            else:
                self.rowcount = 0
        elif sql.startswith("DELETE FROM customers WHERE CustomerID="):
            cid = params[0]
            if cid in self.db['customers']:
                del self.db['customers'][cid]
                self.rowcount = 1
            else:
                self.rowcount = 0
        # Products
        elif sql == "SELECT ProductID, ProductName, Price FROM products":
            rows = []
            for pid, row in sorted(self.db['products'].items()):
                rows.append((pid, row['ProductName'], row.get('Price')))
            self._result = rows
        elif sql.startswith("SELECT ProductID, ProductName, Price FROM products WHERE ProductID="):
            pid = params[0]
            row = self.db['products'].get(pid)
            self._result = (pid, row['ProductName'], row.get('Price')) if row else None
        elif sql.startswith("INSERT INTO products (ProductName, Price) VALUES"):
            name, price = params
            pid = self.db['seq']['products']
            self.db['seq']['products'] += 1
            self.db['products'][pid] = {'ProductName': name, 'Price': float(price)}
            self.lastrowid = pid
            self.rowcount = 1
        elif sql.startswith("UPDATE products SET") and "WHERE ProductID=" in sql:
            *values, pid = params
            if pid in self.db['products']:
                prod = self.db['products'][pid]
                if 'ProductName=' in sql and 'Price=' in sql:
                    prod['ProductName'] = values[0]
                    prod['Price'] = float(values[1])
                elif 'ProductName=' in sql:
                    prod['ProductName'] = values[0]
                elif 'Price=' in sql:
                    prod['Price'] = float(values[0])
                self.rowcount = 1
            else:
                self.rowcount = 0
        elif sql.startswith("DELETE FROM products WHERE ProductID="):
            pid = params[0]
            if pid in self.db['products']:
                del self.db['products'][pid]
                self.rowcount = 1
            else:
                self.rowcount = 0
        # Orders
        elif sql == "SELECT OrderID, CustomerID, ProductID, Quantity FROM orders":
            rows = []
            for oid, row in sorted(self.db['orders'].items()):
                rows.append((oid, row['CustomerID'], row['ProductID'], row['Quantity']))
            self._result = rows
        elif sql.startswith("SELECT OrderID, CustomerID, ProductID, Quantity FROM orders WHERE OrderID="):
            oid = params[0]
            row = self.db['orders'].get(oid)
            self._result = (oid, row['CustomerID'], row['ProductID'], row['Quantity']) if row else None
        elif sql.startswith("INSERT INTO orders (CustomerID, ProductID, Quantity) VALUES"):
            cid, pid, qty = params
            oid = self.db['seq']['orders']
            self.db['seq']['orders'] += 1
            self.db['orders'][oid] = {'CustomerID': cid, 'ProductID': pid, 'Quantity': qty}
            self.lastrowid = oid
            self.rowcount = 1
        elif sql.startswith("UPDATE orders SET") and "WHERE OrderID=" in sql:
            *values, oid = params
            if oid in self.db['orders']:
                ordrow = self.db['orders'][oid]
                idx = 0
                if 'CustomerID=' in sql:
                    ordrow['CustomerID'] = values[idx]; idx += 1
                if 'ProductID=' in sql:
                    ordrow['ProductID'] = values[idx]; idx += 1
                if 'Quantity=' in sql:
                    ordrow['Quantity'] = values[idx]; idx += 1
                self.rowcount = 1
            else:
                self.rowcount = 0
        elif sql.startswith("DELETE FROM orders WHERE OrderID="):
            oid = params[0]
            if oid in self.db['orders']:
                del self.db['orders'][oid]
                self.rowcount = 1
            else:
                self.rowcount = 0
        # Generic exists check used by entity_exists()
        elif sql.startswith("SELECT 1 FROM customers WHERE CustomerID="):
            cid = params[0]
            self._result = (1,) if cid in self.db['customers'] else None
        elif sql.startswith("SELECT 1 FROM products WHERE ProductID="):
            pid = params[0]
            self._result = (1,) if pid in self.db['products'] else None
        elif sql == "SELECT DATABASE()":
            self._result = ("fake_db",)
        else:
            raise NotImplementedError(f"Unsupported SQL: {sql}")

    def fetchone(self):
        if isinstance(self._result, list):
            return self._result[0] if self._result else None
        return self._result

    def fetchall(self):
        if isinstance(self._result, list):
            return self._result
        return [] if self._result is None else [self._result]

    def close(self):
        pass

class FakeConnection:
    def __init__(self, db):
        self.db = db

    def cursor(self):
        return FakeCursor(self.db)

    def commit(self):
        pass

class FakeMySQL:
    def __init__(self, app=None):
        self.connection = FakeConnection({
            'customers': {},
            'products': {},
            'orders': {},
            'seq': {'customers': 1, 'products': 1, 'orders': 1}
        })

@pytest.fixture
def client(monkeypatch):
    from app import app
    # Monkeypatch the mysql object on the app module with our fake
    fake = FakeMySQL(app)
    monkeypatch.setattr(__import__('app'), 'mysql', fake, raising=True)
    app.config['TESTING'] = True
    with app.test_client() as client:
        # Authenticate to obtain JWT for secured endpoints
        login_resp = client.post('/auth/login', json={'username': 'admin', 'password': 'admin'})
        assert login_resp.status_code == 200, f"Login failed: {login_resp.data}"
        token = login_resp.get_json()['access_token']
        # Set default Authorization header for all subsequent requests
        client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
        yield client
