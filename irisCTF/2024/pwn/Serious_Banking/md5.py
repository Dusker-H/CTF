import hashlib

with open('./libc.so.6', 'rb') as f:
    data = f.read()
    md5_hash = hashlib.md5(data).hexdigest()
    print("MD5:", md5_hash)
