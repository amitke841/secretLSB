from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from PIL import Image
import hashlib
import random

def get_encryption_key(password:str, salt: bytes, iterations:int = 500_000) -> bytes :
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 16,
        salt = salt,
        iterations = iterations
    )

    key = kdf.derive(password.encode())
    return key

def encrypt_data(data: bytes,encryption_key: bytes, iv:bytes) -> bytes :
    cipher = Cipher(algorithms.AES128(encryption_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return ct

def decrypt_data(ct: bytes,encryption_key: bytes, iv:bytes) -> str :
    cipher = Cipher(algorithms.AES128(encryption_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ct) + decryptor.finalize()
    return decrypted_data

def get_salt_and_iv(image: Image.Image) -> tuple[bytes, bytes]: #from typing import Tuple
    img_bytes = image.tobytes()[:64]
    salt = bytes([(b >> 2) for b in img_bytes]) #move 2 places right, cant use lsb because it changes
    
    salt = hashlib.sha256(salt).digest()
    iv = hashlib.sha256(salt+ b'iv').digest()[:16]
    return salt, iv

def get_pixel_order(image: Image.Image, encryption_key: bytes) -> list:
    random.seed(encryption_key)
    total_pixels = [(x,y) for x in range(image.width) for y in range(image.height)]
    random.shuffle(total_pixels)
    return total_pixels

def get_length_bits(length: int) -> list:
    binary_str = bin(length)[2:].zfill(18)
    bits = [int(bit) for bit in binary_str]
    return bits #[::-1]

def get_data_bits(data:bytes) -> list:
    bits = []
    for byte in data:
        bits += [(byte >> i) & 1 for i in reversed(range(8))]
    return bits
    
def modify_pixels_rgb(bits_list: list, pixel_order: list, image: Image.Image):
    for pixel, bit in zip(pixel_order, range(0, len(bits_list), 3)):
        r, g, b = image.getpixel(pixel)[:3] #ignore alpha channel if exists
        clear_byte = 0b11111110
        r = r & clear_byte
        g = g & clear_byte
        b = b & clear_byte

        # Only assign bits if they exist
        if bit < len(bits_list):
            r = r | bits_list[bit]
        if bit + 1 < len(bits_list):
            g = g | bits_list[bit + 1]
        if bit + 2 < len(bits_list):
            b = b | bits_list[bit + 2]

        image.putpixel(pixel, (r, g, b))

        
def modify_pixels_l(bits_list: list, pixel_order: list, image: Image.Image):
    for pixel, bit in zip(pixel_order, range(len(bits_list))):
        l = image.getpixel(pixel)
        clear_byte = 0b11111110
        l = l & clear_byte
        l = l | bits_list[bit]
        
        image.putpixel(pixel, l)
        
def read_data_rgb(image: Image.Image, pixel_order: list, length: int) -> list:
    bits = []
    for pixel in pixel_order:
        r, g, b = image.getpixel(pixel)[:3] #ignore alpha channel if exists
        for byte in [r, g, b]:
            if len(bits) < length:
                bits.append(byte & 1)
            else:
                break
        if len(bits) >= length:
            break
    return bits

def read_data_l(image: Image.Image, pixel_order: list, length: int) -> list:
    bits = []
    for pixel in pixel_order:
        l = image.getpixel(pixel)
        if len(bits) < length:
            bits.append(l & 1)
        else:
            break
    return bits
    

def implemet_data(image: Image.Image, pixel_order: list, data: bytes) -> Image.Image: #add pixels for length
    created_image = image.copy()
    pixels_for_length = 6
    if created_image.mode == 'RGB' or created_image.mode == 'RGBA':
        #length 18 bits -> 262,143 chars, TODO print
        if len(data) > (2**(pixels_for_length*3) - 1):
            raise ValueError("data length is too big")
        
        length_bits = get_length_bits(len(data))
        modify_pixels_rgb(length_bits, pixel_order[:pixels_for_length], created_image)
        data_bits = get_data_bits(data)
        modify_pixels_rgb(data_bits, pixel_order[pixels_for_length:], created_image)
        
        return created_image
        
    elif created_image.mode == 'L':
        #length 6 bits -> __ chars
        if len(data) > (2**pixels_for_length - 1):
            raise ValueError("data length is too big")
    
        length_bits = get_length_bits(len(data))
        modify_pixels_l(length_bits, pixel_order[:pixels_for_length], created_image)
        data_bits = get_data_bits(data)
        modify_pixels_l(data_bits, pixel_order[pixels_for_length:], created_image)
        
        return created_image
        
    else: raise TypeError("Only rgb, rgba and grayscale images are supported.")


def extract_data(image: Image.Image, pixel_order: list) -> bytes:
    pixels_for_length = 6 #change
    
    if image.mode == 'RGB' or image.mode == 'RGBA':
        length_bits = read_data_rgb(image, pixel_order, pixels_for_length*3)
        length = int("".join(str(b) for b in length_bits), 2)
        data_bits = read_data_rgb(image, pixel_order[pixels_for_length:], length*8)
        result = bytearray()
        for i in range(0, len(data_bits), 8):
            byte_bits = data_bits[i:i+8]
            byte = 0
            for bit in byte_bits:
                byte = (byte << 1) | bit
            result.append(byte)
        return bytes(result)
        
    elif image.mode == 'L':
        length_bits = read_data_l(image, pixel_order, pixels_for_length)
        length = int("".join(str(b) for b in length_bits), 2)
        data_bits = read_data_l(image, pixel_order[pixels_for_length:], length*8)
        result = bytearray()
        for i in range(0, len(data_bits), 8):
            byte_bits = data_bits[i:i+8]
            byte = 0
            for bit in byte_bits:
                byte = (byte << 1) | bit
            result.append(byte)
        return bytes(result)
    
    else: raise TypeError("Only rgb, rgba and grayscale images are supported.")
    
def encode_image(image: Image.Image, password:str, data:str) -> Image.Image:
    salt, iv = get_salt_and_iv(image)
    
    encryption_key = get_encryption_key(password, salt)
    encrypted_data = encrypt_data(data,encryption_key, iv)
    pixel_order = get_pixel_order(image, encryption_key)
    
    signed_image = implemet_data(image, pixel_order, encrypted_data)
    return signed_image

def decode_image(image: Image.Image, password:str) -> str:
    salt, iv = get_salt_and_iv(image)
    encryption_key = get_encryption_key(password, salt)
    
    pixel_order = get_pixel_order(image, encryption_key)
    encrypted_data = extract_data(image, pixel_order)
    
    data = decrypt_data(encrypted_data, encryption_key, iv)
    return data


