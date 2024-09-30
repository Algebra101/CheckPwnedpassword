import requests
import hashlib
import sys
import re


def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	try:
		res = requests.get(url)
		res.raise_for_status()
	except requests.RequestException as e:
		print(f"Error fetching: {e}")
		return None
	return res


def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0


def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5_char)
	if response:
		return get_password_leaks_count(response, tail)
	else:
		return None


def is_valid_password(password):
	pattern = re.compile(r"(?=^.{8,}$)((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$")
	return bool(pattern.search(password))


def main(password_list):
	for password in password_list:
		if is_valid_password(password):
			count = pwned_api_check(password)
			if count is not None:
				if count:
					print(f'{password} was found {count} times... you should probably change it')
				else:
					print(f'{password} was not found. Carry on!')
			else:
				print(f"Error checking password: {password}")
		else:
			print(f"Password '{password}' does not meet complexity requirements.")

	return 'Done!'


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("Please provide at least one password to check.")
	else:
		sys.exit(main(sys.argv[1:]))
