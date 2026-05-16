import os
import math

def pad_string(text, block_size, pad_char='X'):

    remainder = len(text) % block_size
    if remainder == 0:
        return text
    padding_needed = block_size - remainder
    return text + (pad_char * padding_needed)


def xor_bytes(bytes1, bytes2):

    return bytes(a ^ b for a, b in zip(bytes1, bytes2))


def hex_to_bytes(hex_string):


    return bytes.fromhex(hex_string)


def bytes_to_hex(data):

    return data.hex()


def bytes_to_int(data):

    return int.from_bytes(data, byteorder='big')


def int_to_bytes(number, length=None):

    if length is None:
        # Calculate minimum bytes needed
        length = max(1, math.ceil(number.bit_length() / 8))
    return number.to_bytes(length, byteorder='big')

#----

def generate_random_bytes(n):

    return os.urandom(n)


def generate_random_int(low, high):

    range_size = high - low + 1
    num_bytes = math.ceil(range_size.bit_length() / 8)
    while True:
        candidate = bytes_to_int(os.urandom(num_bytes))
        if candidate < range_size:
            return low + candidate


def is_prime(n):

    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.isqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True


def mod_pow(base, exponent, modulus):

    return pow(base, exponent, modulus)

#----

def display_banner():
    print("       SecureVault")


def clear_screen():


    os.system('cls' if os.name == 'nt' else 'clear')


def print_separator(char='=', length=60):

    print(char * length)


def format_hex_output(label, data):

    if isinstance(data, bytes):
        value = data.hex()
    else:
        value = str(data)
    print(f"  {label:<20}: {value}")