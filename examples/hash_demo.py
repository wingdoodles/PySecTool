import hashlib

password = "test"

# Different hash formats
md5 = hashlib.md5(password.encode()).hexdigest()
sha1 = hashlib.sha1(password.encode()).hexdigest()
sha256 = hashlib.sha256(password.encode()).hexdigest()

print(f"Password: {password}")
print(f"MD5: {md5}")
print(f"SHA1: {sha1}")
print(f"SHA256: {sha256}")
