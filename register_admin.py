import requests
import cmd
import getpass

BASE_URL = 'http://127.0.0.1:5000'

class AdminCLI(cmd.Cmd):
    intro = 'Welcome to the Admin registration CLI. Type help or ? to list commands.\n'
    prompt = '(admin-cli) '

    def do_register(self, arg):
        'Register a new admin: register'
        try:
            username = input('Enter your username: ')
            password = getpass.getpass('Enter your password: ')
            self.register_admin(username, password)
        except Exception as e:
            print(f'Error: {e}')

    def register_admin(self, username, password):
        url = f'{BASE_URL}/admin/register'
        data = {
            'username': username,
            'password': password
        }
        response = requests.post(url, json=data)
        
        if response.status_code == 201:
            print('Admin registered successfully')
        else:
            print(f'Failed to register admin: {response.json()}')

    def do_exit(self, arg):
        'Exit the CLI'
        print('Exiting...')
        return True

if __name__ == '__main__':
    AdminCLI().cmdloop()
