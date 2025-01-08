def fnv1a_hash(data):
    # 초기값 (FNV Offset Basis)
    hash_value = 0xCBF29CE484222325
    # FNV Prime
    fnv_prime = 0x100000001B3

    for byte in data:
        hash_value ^= byte  # XOR with current byte
        hash_value *= fnv_prime  # Multiply by FNV Prime
        hash_value &= 0xFFFFFFFFFFFFFFFF  # Ensure 64-bit result (overflow handling)

    return hash_value

# invite.zip 파일 읽기
with open("invite.zip", "rb") as f:
    file_data = f.read()

# 해시 계산
result = fnv1a_hash("invite.zip")
print(f"FNV-1a hash: {result:#016x}")  # 16진수로 출력
