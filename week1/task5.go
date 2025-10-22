package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Main function
func task5() {
	fmt.Println("\n--------------------------------------------------")
	fmt.Println("Task 5: Binary, Hexadecimal, and Base64 Encoding")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter a string: ")
	input, _ := reader.ReadString('\n')
	s := strings.TrimSpace(input)

	// Displaying formats
	fmt.Printf("Binary: ")
	for i := 0; i < len(s); i++ {
		fmt.Printf("%08b ", s[i])
	}
	fmt.Println()

	fmt.Printf("Hexadecimal: ")
	for i := 0; i < len(s); i++ {
		fmt.Printf("%02x ", s[i])
	}
	fmt.Println()

	fmt.Printf("Base64: %s\n", base64.StdEncoding.EncodeToString([]byte(s)))
}
