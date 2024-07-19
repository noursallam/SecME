import hashlib
import requests
from flag import FlagPrinter

def get_password_hash(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1

def check_password_pwned(password_hash):
    prefix = password_hash[:5]
    suffix = password_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching data: {response.status_code}")
    
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    
    return 0

def main():
    flag_printer = FlagPrinter()
    flag_printer.print_flag()  # Print the flag only once
    
    password = input("Enter the password to check: ")
    password_hash = get_password_hash(password)
    count = check_password_pwned(password_hash)
    print (hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    if count:
        print(f"The password '{password}' has been found {count} times in data breaches. You should change your password.")
    else:
        print(f"The password '{password}' has not been found in any data breaches.")

if __name__ == "__main__":
    main()
