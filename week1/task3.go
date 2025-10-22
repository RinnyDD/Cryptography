package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func task3() {
	fmt.Println("\n--------------------------------------------------")
	fmt.Println("Task 3: Bitwise Operators")

	reader := bufio.NewReader(os.Stdin)

	// Input num1
	fmt.Print("Enter number 1: ")
	num1Str, _ := reader.ReadString('\n')
	num1Str = strings.TrimSpace(num1Str)
	num1, _ := strconv.Atoi(num1Str)

	// Input num2
	fmt.Print("Enter number 2: ")
	num2Str, _ := reader.ReadString('\n')
	num2Str = strings.TrimSpace(num2Str)
	num2, _ := strconv.Atoi(num2Str)

	// Bitwise operations
	fmt.Printf("Bitwise AND: %d\n", num1&num2)
	fmt.Printf("Bitwise OR: %d\n", num1|num2)
	fmt.Printf("Bitwise XOR: %d\n", num1^num2)
	fmt.Printf("Bitwise NOT: %d\n", ^num1)
	fmt.Printf("Left Shift: %d\n", num1<<1)
	fmt.Printf("Right Shift: %d\n", num1>>1)
}
