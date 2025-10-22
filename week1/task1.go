package main
  
import "fmt"
  
// Main function
func task1() {
	fmt.Println("\n-------------------------------------------------- \nTask 1: Swapping and Compound Assignment Operators")
    var num1, num2 int

	// Taking input from user
	fmt.Print("Enter number(num1, num2): ")
	fmt.Scan(&num1, &num2)
	
	// Swapping values
	num1, num2 = num2, num1

	fmt.Printf("After swapping: num1 = %d, num2 = %d\n", num1, num2)

	// += operator
	num1 += num2
	fmt.Printf("After num1 += num2: num1 = %d, num2 = %d\n", num1, num2)

	// -= operator
	num1 -= num2
	fmt.Printf("After num1 -= num2: num1 = %d, num2 = %d\n", num1, num2)

	// *= operator
	num1 *= num2
	fmt.Printf("After num1 *= num2: num1 = %d, num2 = %d\n", num1, num2)

	// /= operator
	num1 /= num2
	fmt.Printf("After num1 /= num2: num1 = %d, num2 = %d\n", num1, num2)

	// %= operator
	num1 %= num2
	fmt.Printf("After num1 %%= num2: num1 = %d, num2 = %d\n", num1, num2)

}
