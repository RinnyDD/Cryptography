package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Task 4: Mini Calculator
func task4() {
	fmt.Println("\n--------------------------------------------------")
	fmt.Println("Task 4: Mini Calculator")

	reader := bufio.NewReader(os.Stdin)

	// Taking input num1
	fmt.Print("Enter number 1: ")
	num1Str, _ := reader.ReadString('\n')
	num1Str = strings.TrimSpace(num1Str)
	num1, err := strconv.ParseFloat(num1Str, 64)
	if err != nil {
		fmt.Println("Invalid number")
		return
	}

	// Taking input num2
	fmt.Print("Enter number 2: ")
	num2Str, _ := reader.ReadString('\n')
	num2Str = strings.TrimSpace(num2Str)
	num2, err := strconv.ParseFloat(num2Str, 64)
	if err != nil {
		fmt.Println("Invalid number")
		return
	}

	// Taking operator
	fmt.Print("Enter operator (+ - * /): ")
	operator, _ := reader.ReadString('\n')
	operator = strings.TrimSpace(operator)

	// Performing calculation
	switch operator {
	case "+":
		fmt.Printf("Result: %.2f\n", num1+num2)
	case "-":
		fmt.Printf("Result: %.2f\n", num1-num2)
	case "*":
		fmt.Printf("Result: %.2f\n", num1*num2)
	case "/":
		if num2 != 0 {
			fmt.Printf("Result: %.2f\n", num1/num2)
		} else {
			fmt.Println("Error: Division by zero")
		}
	default:
		fmt.Println("Error: Invalid operator")
	}
}
