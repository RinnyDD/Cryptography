package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func task6() {
	fmt.Println("\n--------------------------------------------------")
	fmt.Println("Task 6: XOR Encryption and Decryption")

	reader := bufio.NewReader(os.Stdin)

	// Taking input text
	fmt.Print("Enter text to encrypt/decrypt: ")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)

	if text == "" {
		fmt.Println("No text entered, exiting...")
		return
	}

	// Taking key
	fmt.Print("Enter key (text): ")
	keyStr, _ := reader.ReadString('\n')
	keyStr = strings.TrimSpace(keyStr)

	if keyStr == "" {
		fmt.Println("No key entered, exiting...")
		return
	}

	plain := []byte(text)
	key := []byte(keyStr)

	// XOR encrypt (repeating key)
	cipher := make([]byte, len(plain))
	for i := range plain {
		cipher[i] = plain[i] ^ key[i%len(key)]
	}

	// Print encrypted text as base64 (safe for display/transmission)
	encB64 := base64.StdEncoding.EncodeToString(cipher)
	fmt.Printf("Encrypted Text (base64): %s\n", encB64)

	// Decrypting: base64 decode and XOR with same key
	ctBytes, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		fmt.Println("Base64 decode error:", err)
		return
	}

	decrypted := make([]byte, len(ctBytes))
	for i := range ctBytes {
		decrypted[i] = ctBytes[i] ^ key[i%len(key)]
	}

	fmt.Printf("Decrypted Text: %s\n", string(decrypted))
}
