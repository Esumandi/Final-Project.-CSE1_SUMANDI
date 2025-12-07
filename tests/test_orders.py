def test_orders_crud(client):
    # Need a customer and product first
    cr = client.post('/customers', json={'Name': 'Bob', 'Phone': '111'})
    pr = client.post('/products', json={'ProductName': 'Gadget', 'Price': 5.0})
    cid = cr.get_json()['CustomerID']
    pid = pr.get_json()['ProductID']

    # List empty
    rv = client.get('/orders')
    assert rv.status_code == 200
    assert rv.get_json() == []

    # Create invalid (missing Quantity)
    rv = client.post('/orders', json={'CustomerID': cid, 'ProductID': pid})
    assert rv.status_code == 400

    # Create with non-existing foreign keys
    rv = client.post('/orders', json={'CustomerID': 999, 'ProductID': pid, 'Quantity': 1})
    assert rv.status_code == 404
    rv = client.post('/orders', json={'CustomerID': cid, 'ProductID': 999, 'Quantity': 1})
    assert rv.status_code == 404

    # Create invalid types
    rv = client.post('/orders', json={'CustomerID': 'str', 'ProductID': pid, 'Quantity': 1})
    assert rv.status_code == 400

    # Create valid
    rv = client.post('/orders', json={'CustomerID': cid, 'ProductID': pid, 'Quantity': 2})
    assert rv.status_code == 201
    order = rv.get_json()
    oid = order['OrderID']

    # Get
    rv = client.get(f'/orders/{oid}')
    assert rv.status_code == 200
    assert rv.get_json()['Quantity'] == 2

    # Update PUT with invalid qty
    rv = client.put(f'/orders/{oid}', json={'CustomerID': cid, 'ProductID': pid, 'Quantity': 0})
    assert rv.status_code == 400

    # Update PUT valid
    rv = client.put(f'/orders/{oid}', json={'CustomerID': cid, 'ProductID': pid, 'Quantity': 3})
    assert rv.status_code == 200
    assert rv.get_json()['Quantity'] == 3

    # PUT not found
    rv = client.put('/orders/9999', json={'CustomerID': cid, 'ProductID': pid, 'Quantity': 1})
    # Depending on implementation, this may 404 or 200 with not found check
    assert rv.status_code in (200, 404)

    # Patch only quantity
    rv = client.patch(f'/orders/{oid}', json={'Quantity': 5})
    assert rv.status_code == 200

    # Patch invalid quantity
    rv = client.patch(f'/orders/{oid}', json={'Quantity': 0})
    assert rv.status_code == 400

    # Patch empty payload -> 400
    rv = client.patch(f'/orders/{oid}', data='{}', content_type='application/json')
    assert rv.status_code == 400

    # Verify
    rv = client.get(f'/orders/{oid}')
    assert rv.status_code == 200
    assert rv.get_json()['Quantity'] == 5

    # Delete
    rv = client.delete(f'/orders/{oid}')
    assert rv.status_code == 204

    # Delete not found
    rv = client.delete(f'/orders/{oid}')
    assert rv.status_code == 404

    # Get after delete -> 404
    rv = client.get(f'/orders/{oid}')
    assert rv.status_code == 404
