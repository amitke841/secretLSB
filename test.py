from SecretLSB import SecretLSB

secret_lsb = SecretLSB("tests/test1.png","amit")
# secret_lsb.encode_image("hello, this is a secret message".encode())

text = secret_lsb.decode_image()
print(text)
