import requests

# Hardcoded base URL for local development
BASE_URL = "http://localhost:5000"

def register_admin():
    username = input("Enter admin username: ")
    password = input("Enter admin password: ")

    url = f"{BASE_URL}/register/admin"
    data = {
        "username": username,
        "password": password
    }
    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 201:
        print("Admin registered successfully.")
    elif response.status_code == 400:
        print("Admin already exists.")
    else:
        print(f"Failed to register admin. Status code: {response.status_code}")
        print(response.text)

def main():
    register_admin()

if __name__ == "__main__":
    main()
