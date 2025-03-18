# Password-Leak-Checker  

A simple Python script to check if a password has been compromised in data breaches using the **Have I Been Pwned (HIBP) API**.  

## Features  
- Checks if a password appears in known data breaches  
- Uses SHA-1 hashing and k-anonymity for privacy  
- Fast and efficient lookup with minimal data exposure  
- Works via command-line input  

## Installation  
1. Clone this repository:  
```commandline
git clone https://github.com/elijahgbeminiyi/Password-Leak-Checker.git
cd Password-Leak-Checker
```
2. Install dependencies
```commandline
pip3 install -r requirements.txt
```
## Usage
Run the script with passwords as arguments:
```commandline
python3 checkmypass.py yourpassword
```
For multiple passwords:
```commandline
python3 checkmypass.py passwor1 password2 password3
```

#### _Stay secure! Change your passwords if they have been compromised!_