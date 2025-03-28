import pytest
from app import app, db, User
from app import shared_content


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client


def test_register(client):
    response = client.post('/register', json={
        'username': 'tetsuser',
        'password': 'testpass',
    })

    assert response.status_code == 201
    assert b'User registered successfully' in response.data


def test_login(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': 'testpass'
    })

    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })

    assert response.status_code == 200
    json_data = response.get_json()
    assert 'access_token' in json_data
    assert 'refresh_token' in json_data


def test_viewer_access(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': 'testpass'
    })

    login_res = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })

    access_token = login_res.get_json()['access_token']
    share_cont_res = client.get('/shared-content', headers={'Authorization': f'Bearer {access_token}'})
    admin_cont_res = client.get('/admin-only', headers={'Authorization': f'Bearer {access_token}'})

    assert share_cont_res.status_code == 200
    assert 'viewer' in share_cont_res.get_json()['message']
    assert admin_cont_res.status_code == 403
    assert 'Not an admin' in admin_cont_res.get_json()['message']


def test_admin_access(client):
    client.post('/register', json={
        'username': 'adminuser',
        'password': 'adminpass',
        'role': 'admin'
    })

    login_res = client.post('/login', json={
        'username': 'adminuser',
        'password': 'adminpass'
    })

    access_token = login_res.get_json()['access_token']
    admin_cont_res = client.get('/admin-only', headers={'Authorization': f'Bearer {access_token}'})
    share_cont_res = client.get('/shared-content', headers={'Authorization': f'Bearer {access_token}'})

    assert share_cont_res.status_code == 200
    assert 'admin' in share_cont_res.get_json()['message']
    assert admin_cont_res.status_code == 200
    assert 'admin' in admin_cont_res.get_json()['message']


def test_access_without_token(client):
    share_cont_res = client.get('/shared-content')
    admin_cont_res = client.get('/admin-only')

    assert share_cont_res.status_code == 401
    assert 'Missing Authorization Header' in share_cont_res.get_json()['msg']

    assert admin_cont_res.status_code == 401
    assert 'Missing Authorization Header' in admin_cont_res.get_json()['msg']


def test_logout_revokes_token(client):
    client.post('/register', json={
        'username': 'testuser',
        'password': 'testpass'
    })

    login_res = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    access_token = login_res.get_json()['access_token']
    logout_res = client.post('/logout', headers={'Authorization': f'Bearer {access_token}'})

    assert logout_res.status_code == 200
    assert 'User logout successfully' in logout_res.get_json()['message']

    protected_res = client.get('/shared-content', headers={'Authorization': f'Bearer {access_token}'})

    assert protected_res.status_code == 401
