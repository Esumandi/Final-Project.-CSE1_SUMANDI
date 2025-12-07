def test_products_crud(client):
    # List empty
    rv = client.get('/products')
    assert rv.status_code == 200
    assert rv.get_json() == []

    # Create invalid (missing Price)
    rv = client.post('/products', json={'ProductName': 'Widget'})
    assert rv.status_code == 400

    # Create invalid price negative
    rv = client.post('/products', json={'ProductName': 'Bad', 'Price': -1})
    assert rv.status_code == 400

    # Create valid
    rv = client.post('/products', json={'ProductName': 'Widget', 'Price': 9.99})
    assert rv.status_code == 201
    prod = rv.get_json()
    pid = prod['ProductID']

    # Get
    rv = client.get(f'/products/{pid}')
    assert rv.status_code == 200
    assert rv.get_json()['ProductName'] == 'Widget'

    # Update with PUT
    rv = client.put(f'/products/{pid}', json={'ProductName': 'Widget Pro', 'Price': 19.99})
    assert rv.status_code == 200
    assert rv.get_json()['Price'] == 19.99

    # PUT not found
    rv = client.put('/products/9999', json={'ProductName': 'Ghost', 'Price': 1.0})
    assert rv.status_code in (200, 404)

    # Patch only price
    rv = client.patch(f'/products/{pid}', json={'Price': 29.99})
    assert rv.status_code == 200

    # Patch invalid price
    rv = client.patch(f'/products/{pid}', json={'Price': -5})
    assert rv.status_code == 400

    # Patch empty payload -> 400
    rv = client.patch(f'/products/{pid}', data='{}', content_type='application/json')
    assert rv.status_code == 400

    # Verify
    rv = client.get(f'/products/{pid}')
    assert rv.status_code == 200
    assert rv.get_json()['Price'] == 29.99

    # Delete
    rv = client.delete(f'/products/{pid}')
    assert rv.status_code == 204

    # Delete not found
    rv = client.delete(f'/products/{pid}')
    assert rv.status_code == 404

    # Get after delete -> 404
    rv = client.get(f'/products/{pid}')
    assert rv.status_code == 404
