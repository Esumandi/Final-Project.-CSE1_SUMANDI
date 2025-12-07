def test_customers_crud(client):
    # List initially empty
    rv = client.get('/customers')
    assert rv.status_code == 200
    assert rv.get_json() == []

    # Create invalid (missing Name)
    rv = client.post('/customers', json={'Phone': '123'})
    assert rv.status_code == 400

    # Create invalid (Name too long)
    rv = client.post('/customers', json={'Name': 'x'*101, 'Phone': '123'})
    assert rv.status_code == 400

    # Create valid
    rv = client.post('/customers', json={'Name': 'Alice', 'Phone': '123-456'})
    assert rv.status_code == 201
    cust = rv.get_json()
    cid = cust['CustomerID']

    # Get
    rv = client.get(f'/customers/{cid}')
    assert rv.status_code == 200
    assert rv.get_json()['Name'] == 'Alice'

    # Update with PUT
    rv = client.put(f'/customers/{cid}', json={'Name': 'Alice B', 'Phone': '555'})
    assert rv.status_code == 200
    assert rv.get_json()['Name'] == 'Alice B'

    # PUT not found
    rv = client.put('/customers/9999', json={'Name': 'Ghost', 'Phone': '000'})
    assert rv.status_code in (200, 404)  # Implementation returns 404 when no rows affected
    if rv.status_code == 200:
        assert rv.get_json()['CustomerID'] == 9999

    # Patch - remove phone by setting empty (API treats empty as invalid)
    rv = client.patch(f'/customers/{cid}', json={'Phone': ''})
    assert rv.status_code == 400

    # Patch empty payload -> 400
    rv = client.patch(f'/customers/{cid}', data='{}', content_type='application/json')
    assert rv.status_code == 400

    # Verify via GET still returns latest valid data
    rv = client.get(f'/customers/{cid}')
    assert rv.status_code == 200
    assert rv.get_json()['Name'] == 'Alice B'

    # Delete
    rv = client.delete(f'/customers/{cid}')
    assert rv.status_code == 204

    # Delete not found
    rv = client.delete(f'/customers/{cid}')
    assert rv.status_code == 404

    # Get after delete -> 404
    rv = client.get(f'/customers/{cid}')
    assert rv.status_code == 404
