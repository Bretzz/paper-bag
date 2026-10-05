## About Paper Bag
This is a Reverse Proxy service that blocks certain routes behind authentication. Each route will have it's own username and password.

### Vulnerabilities
- Usernames and passwords are kept as plain text
- The JWT secret is static, never changes

### routes.json
This file contains all the routes the proxy handles. Use the following format
```json
{
    "public_routes": [
        {
            "URL": "www.example.com/"
        }
    ],
    "protected_routes": [
        {
            "URL": "www.example.com/projectX",
            "username": "username",
            "password": "secret_password"
        },
        {
            "URL": "drive.example.com",
            "username": "username",
            "password": "secret_password"
        }
    ]
}
```