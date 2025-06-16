# Password Security Checker

## Overview
This Python script checks whether a given password has been compromised by querying the [Have I Been Pwned API](https://haveibeenpwned.com/). It also verifies that the password meets basic complexity requirements.

## Features
- Uses SHA-1 hashing to check passwords securely against leaked databases.
- Validates password complexity based on length, uppercase/lowercase letters, numbers, and special characters.
- Provides feedback on whether a password has been found in breaches and how many times.
- Handles API requests efficiently and includes error handling.

## Requirements
- Python 3.x
- `requests` module (install using `pip install requests`)

## Installation
1. Clone or download the script to your local machine.
2. Install dependencies using:

   ```sh
   pip install requests
   ```

3. Run the script with:

   ```sh
   python password_checker.py mypassword1 mypassword2
   ```

## Usage
Provide one or more passwords as command-line arguments:

```sh
python password_checker.py Password123! MySecurePass
```

### Output Example
```
Password123! was found 10430 times... you should probably change it
MySecurePass was not found. Carry on!
```

## How It Works
1. Password is hashed using SHA-1 and split into two parts.
2. The first five characters of the hash are sent to the Have I Been Pwned API.
3. The API returns all matching hash suffixes.
4. The script checks if the full password hash exists in the breach database.
5. If found, the number of breaches is displayed.

## Security Considerations
- The script follows the k-Anonymity principle, ensuring passwords are not fully exposed to the API.
- Always use strong, unique passwords for each service.
- Consider a password manager to generate and store secure passwords.

## License
This project is open-source and free to use.
