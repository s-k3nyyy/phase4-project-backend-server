import requests
import json

# Flask server URL where your application is running
BASE_URL = 'http://localhost:5000'

def register_admin(username, email, password):
    url = f'{BASE_URL}/register/admin'
    data = {
        'username': username,
        'email': email,
        'password': password
    }
    headers = {
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))
        if response.status_code == 201:
            print('Admin registered successfully.')
        else:
            print(f'Failed to register admin: {response.json()}')
    except requests.exceptions.RequestException as e:
        print(f'Error registering admin: {str(e)}')

if __name__ == '__main__':
    username = input('Enter admin username: ')
    email = input('Enter admin email: ')
    password = input('Enter admin password: ')

    register_admin(username, email, password)
