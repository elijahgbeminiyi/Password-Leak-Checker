import requests
import hashlib
import sys


def request_api_data(query_char):
    """
    Requests data from the Have I Been Pwned (HIBP) API using the first 5 characters
    of the SHA-1 hash of a password.

    :raises RuntimeError: If the API request fails.

    :param query_char: The first 5 characters of the hashed password.

    :return Response object: The API response containing leaked password hash suffixes.
    """
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    """
    Checks if the given password hash suffix appears in the leaked password data.

    :param hashes: The API response containing password hash suffixes and their leak counts.
    :param hash_to_check: The remaining part of the SHA-1 hash to check.

    :return int: The number of times the password has been found in breaches.
    """
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    """
    Checks if a given password has been exposed in data breaches using the HIBP API.

    :param password: The password to check (str).

    :return: The number of times the password has been found in breaches (int).
    """

    # Convert password to SHA-1 hash and format for the HIBP API
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]

    # Query the API using the first 5 characters of the SHA-1 hash
    response = request_api_data(first5_char)

    # Check if the remaining hash exists in the API response
    return get_password_leaks_count(response, tail)

def main(args):
    """
    Checks a list of passwords against the HIBP API and displays results.

    :param args: List of passwords provided as command-line arguments (list).
    :return: 'done' after processing all passwords (str).
    """
    for password in args:
        count = pwned_api_check(password)

        # Mask all but the first two characters of the password for privacy
        masked_password = f'{password[:2]}{"*" * (len(password) - 2)}'

        if count:
            print(f'{masked_password} was found {count} times...you should consider changing your password')
        else:
            print(f'{masked_password} was not found. Carry on!')
    return 'done'

if __name__ == '__main__':

    # Execute the script with command-line arguments and exit with the appropriate status
    sys.exit(main(sys.argv[1:]))