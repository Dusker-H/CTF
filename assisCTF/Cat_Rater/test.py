import re

# cat-urls.txt 파일 읽기
with open('cat-urls.txt', 'r') as f:
    urls = f.readlines()

# 필터 조건에 걸리지 않는 URL 추출
valid_urls = []
for link in urls:
    link = link.strip()  # 양끝 공백 제거
    if link and not re.search(r'[\x00-\x20\[\]%{}\-]', link) and link.isascii():
        valid_urls.append(link)

# 결과 출력
print("필터링에 걸리지 않는 URL:")
for url in valid_urls:
    print(url)
