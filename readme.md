# 🔐 SecretLSB – LSB Steganography with Encryption & Password-Based Pixel Shuffling

SecretLSB is a Python implementation of **LSB image steganography** combined with **strong encryption**.  
It hides encrypted data inside PNG images while using **two independent security layers derived from a single password**:

- **Data encryption** (AES-128)
- **Password-based pixel order shuffling**

Even if an attacker suspects steganography, extracting meaningful data without the password is computationally impossible.



## 🧠 Example

| ![Original](tests/test1.png) | ![Modifed](tests/test2.png) |
|-------------------------|----------------------|
| Original Image          | Image with Hidden Data |

---
The message `hello, this is a secret message` is embedded within the image using LSB steganography.
There are no visible changes to the image, and even at the raw byte level, the modifications are minimal and indistinguishable from natural image noise.

## 🚀 How to Run & Use

### Install Dependencies
```bash
pip install -r requirements.txt
```
### Encode a Message
```python
import SecretLSB

lsb = SecretLSB.SecretLSB("image.png", "my_password")
lsb.encode_image(b"hello, this is a secret message")
```
### Decode the Message

```python
lsb = SecretLSB.SecretLSB("image.png", "my_password")
message = lsb.decode_image()
print(message)
```
>⚠️ The image must be PNG, and the same password is required to decode the message.

> **ℹ️ Info:** if needed, convertToPng() built in function can be used -> `from SecretLSB import convertToPng`





---

## 🛡️ Security Model (Two Factors)

### 1️⃣ Encrypted Payload
The hidden message is encrypted using:

- **AES-128 in CTR mode**
- Key derived from the password using **PBKDF2**
- 500,000 iterations
- SHA-256 hash

Without the correct password, extracted bits are indistinguishable from random noise.

---

### 2️⃣ Password-Based Pixel Shuffling
Instead of embedding data sequentially, pixel positions are:

- Deterministically shuffled using `random.seed(encryption_key)`
- Fully dependent on the derived encryption key

➡️ Even if an attacker reads LSBs correctly, the bit order will be wrong without the password.
###  Protection from attacks(like hash rainbow tables)

To avoid attempts to disclose information, this project uses salt and IV(initial vector for AES).

- **Salt** is derived from the image itself
- **IV** is derived from the salt
- **No salt or IV** is stored externally - these values are not a secret.

This ensures:
- Same image + same password → same key
- Modified image → different key


## 🧠 How Data Is Stored

### Length Encoding
- First **6 pixels** are reserved for payload length
- Length stored in **18 bits** (RGB)  
  → max payload: **262,143 bytes**

### Data Encoding
- Each pixel stores up to **3 bits** (1 per color channel)
- Uses **LSB only**
- Alpha channel (if present) is ignored

