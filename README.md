# EUGENE SUMANDI — Flask REST API (Customers, Products,  Orders)



Quick install

1. Create & activate venv:

    ```bash
    python -m venv venv
    source venv/bin/activate
    ```
2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

Run (dev)

```bash
python app.py    # serves on 127.0.0.1:5000
```


API (short)

- GET /                → health
- GET /testdb          → returns database name
- POST /auth/login     → {username,password} → {access_token}
- /customers           → GET, POST, GET/{id}, PUT, PATCH, DELETE
- /products            → GET, POST, GET/{id}, PUT, PATCH, DELETE
- /orders              → GET, POST, GET/{id}, PUT, PATCH, DELETE

Quick examples (curl)

Obtain token:

```bash
curl -s -X POST http://127.0.0.1:5001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

Create product (admin):

```bash
curl -s -X POST http://127.0.0.1:5001/products \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"ProductName":"Gizmo","Price":5.0}'
```

Create customer (admin):

```bash
curl -s -X POST http://127.0.0.1:5001/customers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"Name":"Alice","Phone":"123-456"}'
```

Create order (no auth required by default):

```bash
curl -s -X POST http://127.0.0.1:5001/orders \
  -H "Content-Type: application/json" \
  -d '{"CustomerID":1,"ProductID":1,"Quantity":2}'
```

