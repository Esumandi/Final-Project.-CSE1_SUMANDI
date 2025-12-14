def test_customers_search(client):
    # create customers
    client.post('/customers', json={'Name': 'Alice', 'Phone': '111'})
    client.post('/customers', json={'Name': 'Alicia', 'Phone': '222'})
    client.post('/customers', json={'Name': 'Bob', 'Phone': '333'})

    rv = client.get('/customers?name=Ali')
    assert rv.status_code == 200
    res = rv.get_json()
    assert isinstance(res, list)
    names = sorted([c['Name'] for c in res])
    assert names == ['Alice', 'Alicia']

    rv = client.get('/customers?q=alice')
    assert rv.status_code == 200
    res = rv.get_json()
    assert len(res) == 1
    assert res[0]['Name'] == 'Alice'

    rv = client.get('/customers?name=Nonexist')
    assert rv.status_code == 200
    assert rv.get_json() == []


def test_customers_search_invalid_param(client):
    long = 'x' * 201
    rv = client.get(f'/customers?name={long}')
    assert rv.status_code == 400


def test_products_search_name_and_price(client):
    client.post('/products', json={'ProductName': 'Widget', 'Price': 9.99})
    client.post('/products', json={'ProductName': 'Widget Pro', 'Price': 19.99})
    client.post('/products', json={'ProductName': 'Cheap', 'Price': 1.0})

    rv = client.get('/products?name=Widget&min_price=10')
    assert rv.status_code == 200
    res = rv.get_json()
    assert isinstance(res, list)
    assert len(res) == 1
    assert res[0]['ProductName'] == 'Widget Pro'

    rv = client.get('/products?min_price=bad')
    assert rv.status_code == 400


def test_orders_search_by_ids_and_customer_name(client):
    # setup
    cr = client.post('/customers', json={'Name': 'Charlie', 'Phone': '444'})
    pr = client.post('/products', json={'ProductName': 'Gizmo', 'Price': 5.0})
    cid = cr.get_json()['CustomerID']
    pid = pr.get_json()['ProductID']

    # create an order
    rv = client.post('/orders', json={'CustomerID': cid, 'ProductID': pid, 'Quantity': 3})
    assert rv.status_code == 201

    rv = client.get(f'/orders?customer_id={cid}')
    assert rv.status_code == 200
    res = rv.get_json()
    assert isinstance(res, list)
    assert any(o['CustomerID'] == cid for o in res)

    rv = client.get('/orders?customer_name=charlie')
    assert rv.status_code == 200
    res = rv.get_json()
    assert any(o['CustomerID'] == cid for o in res)

    rv = client.get('/orders?customer_id=notint')
    assert rv.status_code == 400

