# Applied Cryptography Project

## Overview
This class project demonstrates authentication, access control, and cryptography in Python.  
It implements secure password hashing, login verification, file access control, and basic cryptographic operations using modern best practices.

## Features
- **User account creation** with securely hashed passwords  
- **Secure login system** with password verification  
- **File creation and access control** per user  
- **Persistent JSON storage** for user accounts and access control lists (ACLs)  
- **Cryptography integration** using the `cryptography` library  
- Fail-safe defaults for security and data integrity

## Project Structure
applied-cryptography/
├── main.py # Entry point of the program
├── AAC_Project/code/CryptoProject.py # Cryptography utility class
├── users.json # Persistent storage for users (initially empty)
└── acl.json # Persistent storage for ACLs (initially empty)


## Technologies
- Python  
- Cryptography library (`cryptography`)  
- JSON for persistent storage

## How to Run
1. Clone the repository
``` bash
git clone https://github.com/yourusername/applied-cryptography.git
```
2. Install dependencies:
```bash
pip install -r requirements.txt
```
3. Run the program:

```bash
python main.py
```


## Notes
Security: This project is for educational purposes. Do not use this system for real sensitive data.
JSON files: users.json and acl.json are empty on upload; the program populates them at runtime.
