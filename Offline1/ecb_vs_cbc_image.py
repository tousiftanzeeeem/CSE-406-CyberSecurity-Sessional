from PIL import Image
import os
from task1 import ecb_encrypt, cbc_encrypt, key_expansion, normalize_key, BLOCK_SIZE

img = Image.open("buet-logo-bangladesh-university-of-engineering-and-technology-emblem-free-vector.jpg").resize((64, 64)).convert("RGB")
pixels = img.tobytes()
keys = key_expansion(normalize_key("MySecretKey"))

ecb_ct = ecb_encrypt(pixels, keys)
cbc_ct = cbc_encrypt(pixels, keys, os.urandom(BLOCK_SIZE))

# Save directy as BMP (Pillow handles the header)
for name, data in [("ecb_encrypted.bmp", ecb_ct), ("cbc_encrypted.bmp", cbc_ct)]:
    Image.frombytes("RGB", (64, 64), data[:len(pixels)]).save(name, "BMP")

print("Files saved.")