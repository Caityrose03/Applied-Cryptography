import json
from AAC_Project.code.CryptoProject import CryptoProject
from cryptography.fernet import Fernet

# Initialize CryptoProject class
crypto = CryptoProject()  # Added: initialize CryptoProject for password hashing and verification

# File to store user accounts
# You can implement the backing store using a database or other methods as you like
USER_FILE = "users.json"
ACL_FILE = "acl.json"  

# You must use the following two classes and their methods. You can add methods,
# you can change the arguments coming into the methods, but you must use these
# classes and methods and do not change their names.

# To use the JSON files for backend storage, you can use the following functions:
# To write to a json file:
# with open('filename.json', 'w') as file:
# json.dump(data, file)
# To read from a json file:
# with open('filename.json', 'r') as file:
# data = json.load(file)
# See https://www.w3schools.com/python/python_json.asp for more information
#
# NOTE: You need to figure out how you will use your JSON files to store user
# accounts and ACLs before you start coding your project.

class Authentication():
    def __init__(self):
        return
    
    def load_users(self):
        """Load users from persistent storage."""
        try:
            with open(USER_FILE, 'r') as file:
                return json.load(file)  #loads existing usernames and hashed passwords
        except FileNotFoundError:
            return {}  # return empty dict if file does not exist

    def save_users(self, users):
        # TODO: Save users to persistent storage.
        # save user dictionary to file immediately
        with open(USER_FILE, 'w') as file:
            json.dump(users, file) # this writes the user data to the json file
            # https://www.geeksforgeeks.org/python/file-flush-method-in-python/ 
            file.flush()  #.flush() method ensures data is written to disk so that no data is lost if program crashes and allows the data to be used immediately while programming is running
        return

    def create_account(self, users):
        # TODO: Implement account creation
        username = input("Create a username: ")
        password = input("Create a password: ")

        # TODO: Check if username already exists
        if username in users:  # prevent duplicate usernames. If the username already exists it will overwrite the existing user.
            print("Username already exists. Please choose a different username.")
            return None
        
        # TODO: Store password securely
        hashed_password = crypto.hash_string(password)  # Using hashing to store password instead of plaintext
        users[username] = hashed_password
        print(f"Account created for {username}.")

        # TODO: Save updated user list
        # save the new user immediately
        self.save_users(users) 
        return username  # return username so ACL entry can be created

    def login(self, users):
        username = input("Enter username: ")
        password = input("Enter password: ")

        # TODO: Implement login method including secure password check
        if username in users and crypto.verify_integrity(password, users[username]): # Fail-safe defaults: only allow login if both username exists and password matches
            # secure verification against hashed password
            print(f"Login successful. Welcome, {username}!")
            return None
        else:
            print(f"Login failed for {username}. Incorrect username or password.")
            return username


class AccessControl():
    def __init__(self):
        return

    def load_acl(self):
        # TODO: Load ACL (Access Control List) from persistent storage.
        try:
            with open(ACL_FILE, 'r') as file:
                return json.load(file)  # load user-to-file access mapping 
        except FileNotFoundError:
            return {}  # return empty dict if ACL file does not exist

    def save_acl(self, acl):
        #TODO: Save ACL to persistent storage.
        with open(ACL_FILE, 'w') as file:
            json.dump(acl, file)
            file.flush()  # ensure ACL changes are saved immediately so that no access control data is lost if program crashes
        return

    def create_file(self, username, acl):
        filename = input("Enter the name of the file you want to create: ")
        content = input("Enter content for the file: ")

        # Create the file and write content 
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(content)
        except Exception as e:
            print(f"Error creating file: {e}")
            return

        # Add file access entry in ACL
        if username not in acl:
            acl[username] = []  # initialize user's ACL list if not exists
        if filename not in acl[username]:
            acl[username].append(filename)  # grant user access to file

        self.save_acl(acl)  # persist ACL immediately (Fail-Safe Defaults)
        print(f"File '{filename}' created and access granted to {username}.")
    
    def read_file(self, username, acl):
        filename = input("Enter the name of the file you want to read: ")

        # Check if the user has access (Fail-safe: deny by default)
        if username in acl and filename in acl[username]:
            print("Access granted.")
        else:
            print("Access denied.")
            return

        # Read the file as plain text 
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                content = file.read()
            print(f"Content of '{filename}':\n{content}")
        except FileNotFoundError:
            print("File not found.")
        except Exception as e:
            print(f"Error reading file: {e}")
        return




def main():
    auth = Authentication()
    ac = AccessControl()
    
    users = auth.load_users() 
    acl = ac.load_acl()    

    while True:
        print("\n--- Authentication & Access Control ---")
        print("1. Create an account")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ")
        if choice == '1':
            new_user = auth.create_account(users)
            if new_user:
                if new_user not in acl:
                    acl[new_user] = []
                    ac.save_acl(acl) 
        elif choice == '2':
            user = auth.login(users)
            if user:
                # If login is successful, show file options
                while True:
                    print("\n1. Create a file")
                    print("2. Read a file")
                    print("3. Logout")

                    file_choice = input("Enter your choice: ")
                    
                    if file_choice == '1':
                        ac.create_file(user, acl)
                    elif file_choice == '2':
                        ac.read_file(user, acl)    
                    elif file_choice == '3':
                        print(f"Logging out {user}.")
                        break
                    else:
                        print("Invalid choice.")
        elif choice == '3':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
