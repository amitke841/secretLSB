from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from PIL import Image
import hashlib
import random

def convetToPng(image: Image.Image):
    image.save("converted.png")


class SecretLSB:
    
    def __init__(self, PNG_IMAGE_file_path: str, password: str):
        self._file_path = PNG_IMAGE_file_path
        self._image = Image.open(self._file_path)
        if(self._image.format != "PNG"): raise TypeError("File must be png. can use convert function")
        self._password = password
        self._salt, self._iv = self._get_salt_and_iv(self._image)
        self._encryption_key = self._get_encryption_key(self._password, self._salt)
        self._pixel_order = self._get_pixel_order(self._image, self._encryption_key)

    
    
    
    def encode_image(self, data:str):
        encrypted_data = self._encrypt_data(data,self._encryption_key, self._iv)
        
        signed_image = self._implemet_data(self._image, self._pixel_order, encrypted_data)
        self._image = signed_image
        self._image.save(self._file_path)

    def decode_image(self) -> str:        
        encrypted_data = self._extract_data(self._image, self._pixel_order)
        
        data = self._decrypt_data(encrypted_data, self._encryption_key, self._iv)
        return data
    
    
    
    
    #INNER FUNCS
    
    def _get_encryption_key(self, password:str, salt: bytes, iterations:int = 500_000) -> bytes :
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 16,
            salt = salt,
            iterations = iterations
        )

        key = kdf.derive(password.encode())
        return key

    def _encrypt_data(self, data: bytes,encryption_key: bytes, iv:bytes) -> bytes :
        cipher = Cipher(algorithms.AES128(encryption_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return ct

    def _decrypt_data(self, ct: bytes,encryption_key: bytes, iv:bytes) -> str :
        cipher = Cipher(algorithms.AES128(encryption_key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ct) + decryptor.finalize()
        return decrypted_data

    def _get_salt_and_iv(self, image: Image.Image) -> tuple[bytes, bytes]: #from typing import Tuple
        img_bytes = image.tobytes()[:64]
        salt = bytes([(b >> 2) for b in img_bytes]) #move 2 places right, cant use lsb because it changes
        
        salt = hashlib.sha256(salt).digest()
        iv = hashlib.sha256(salt+ b'iv').digest()[:16]
        return salt, iv

    def _get_pixel_order(self, image: Image.Image, encryption_key: bytes) -> list:
        random.seed(encryption_key)
        total_pixels = [(x,y) for x in range(image.width) for y in range(image.height)]
        random.shuffle(total_pixels)
        return total_pixels

    def _get_length_bits(self, length: int) -> list:
        binary_str = bin(length)[2:].zfill(18)
        bits = [int(bit) for bit in binary_str]
        return bits #[::-1]

    def _get_data_bits(self, data:bytes) -> list:
        bits = []
        for byte in data:
            bits += [(byte >> i) & 1 for i in reversed(range(8))]
        return bits
        
    def _modify_pixels_rgb(self, bits_list: list, pixel_order: list, image: Image.Image):
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

            
    def _modify_pixels_l(self, bits_list: list, pixel_order: list, image: Image.Image):
        for pixel, bit in zip(pixel_order, range(len(bits_list))):
            l = image.getpixel(pixel)
            clear_byte = 0b11111110
            l = l & clear_byte
            l = l | bits_list[bit]
            
            image.putpixel(pixel, l)
            
    def _read_data_rgb(self, image: Image.Image, pixel_order: list, length: int) -> list:
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

    def _read_data_l(self, image: Image.Image, pixel_order: list, length: int) -> list:
        bits = []
        for pixel in pixel_order:
            l = image.getpixel(pixel)
            if len(bits) < length:
                bits.append(l & 1)
            else:
                break
        return bits
        

    def _implemet_data(self, image: Image.Image, pixel_order: list, data: bytes) -> Image.Image: #add pixels for length
        created_image = image.copy()
        pixels_for_length = 6
        if(created_image.mode == "P"): created_image = created_image.convert("RGB")
        if created_image.mode == 'RGB' or created_image.mode == 'RGBA':
            #length 18 bits -> 262,143 chars, TODO print
            if len(data) > (2**(pixels_for_length*3) - 1):
                raise ValueError("data length is too big")
            
            length_bits = self._get_length_bits(len(data))
            self._modify_pixels_rgb(length_bits, pixel_order[:pixels_for_length], created_image)
            data_bits = self._get_data_bits(data)
            self._modify_pixels_rgb(data_bits, pixel_order[pixels_for_length:], created_image)
            
            return created_image
            
        elif created_image.mode == 'L':
            #length 6 bits -> __ chars
            if len(data) > (2**pixels_for_length - 1):
                raise ValueError("data length is too big")
        
            length_bits = self._get_length_bits(len(data))
            self._modify_pixels_l(length_bits, pixel_order[:pixels_for_length], created_image)
            data_bits = self._get_data_bits(data)
            self._modify_pixels_l(data_bits, pixel_order[pixels_for_length:], created_image)
            
            return created_image
            
        else: raise TypeError("Only rgb, rgba and grayscale images are supported.")


    def _extract_data(self, image: Image.Image, pixel_order: list) -> bytes:
        pixels_for_length = 6 #change
        
        if image.mode == 'RGB' or image.mode == 'RGBA':
            length_bits = self._read_data_rgb(image, pixel_order, pixels_for_length*3)
            length = int("".join(str(b) for b in length_bits), 2)
            data_bits = self._read_data_rgb(image, pixel_order[pixels_for_length:], length*8)
            result = bytearray()
            for i in range(0, len(data_bits), 8):
                byte_bits = data_bits[i:i+8]
                byte = 0
                for bit in byte_bits:
                    byte = (byte << 1) | bit
                result.append(byte)
            return bytes(result)
            
        elif image.mode == 'L':
            length_bits = self._read_data_l(image, pixel_order, pixels_for_length)
            length = int("".join(str(b) for b in length_bits), 2)
            data_bits = self._read_data_l(image, pixel_order[pixels_for_length:], length*8)
            result = bytearray()
            for i in range(0, len(data_bits), 8):
                byte_bits = data_bits[i:i+8]
                byte = 0
                for bit in byte_bits:
                    byte = (byte << 1) | bit
                result.append(byte)
            return bytes(result)
        
        else: raise TypeError("Only rgb, rgba and grayscale images are supported.")