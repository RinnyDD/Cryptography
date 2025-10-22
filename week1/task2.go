package main

import "fmt"

// Main function
func task2() {
	fmt.Println("\n-------------------------------------------------- \nTask 2: Relational and Logical Operators")
	//Logical Operators
	var a, b bool
	a = true
	b = false
	fmt.Printf("a AND b: %t\n", a && b)
	fmt.Printf("a OR b: %t\n", a || b)
	fmt.Printf("NOT a: %t\n", !a)
}