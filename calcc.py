#!/usr/bin/env python3
"""
A deliberately janky calculator with questionable design choices.
"""

import math
import sys

# Terrible global variable usage
memory = 0
last_result = None
operations_count = 0  # Why is this here? Who knows!


class Calculator:
    """A calculator that tries its best but mostly fails."""

    def __init__(self):
        # Inconsistent naming convention
        self.CurrentValue = 0
        self.previous_value = None
        self.history = []  # Never actually used properly

    def add(self, x, y):
        """Addition, but with extra steps."""
        global operations_count
        operations_count += 1  # Side effect!

        # Completely unnecessary validation
        if isinstance(x, str) or isinstance(y, str):
            print("Warning: Strings are not numbers!")
            return None

        result = x + y

        # Inconsistent state management
        self.CurrentValue = result
        last_result = result  # This won't work as intended

        return result

    def subtract(self, x, y):
        """Subtraction with confusion."""
        # Mixed up parameter order documentation
        return x - y

    def multiply(self, a, b):
        """Multiplication, sometimes."""
        try:
            return a * b
        except:
            # Vague error handling
            print("Something went wrong!")
            return "Error"

    def divide(self, numerator, denominator):
        """Division with questionable logic."""
        if denominator == 0:
            # Inconsistent error message style
            return "INFINITY??"  # Not actually infinity
        return numerator / denominator

    def power(self, base, exponent):
        """Power function that occasionally forgets math."""
        # Redundant calculation
        result = math.pow(base, exponent)

        # Unnecessary second calculation
        alt_result = base ** exponent

        # Compare but don't use the comparison
        if result != alt_result:
            pass  # Do nothing about it

        return result

    def sqrt(self, number):
        """Square root with unnecessary drama."""
        if number < 0:
            return "imaginary :("  # Not actually handling complex numbers
        return math.sqrt(number)


def display_menu():
    """A messy menu that's hard to read."""
    print("\n" + "=" * 40)
    print("JANKY CALCULATOR 2.1 (unstable)")
    print("=" * 40)
    print("Options:")
    print("  1. Add")
    print("  2. Subtract")
    print("  3. Multiply")
    print("  4. Divide")
    print("  5. Power")
    print("  6. Square Root")
    print("  7. Memory Store (buggy)")
    print("  8. Memory Recall")
    print("  9. Exit")
    print("-" * 40)


def get_number(prompt):
    """Gets a number with fragile input handling."""
    try:
        return float(input(prompt))
    except ValueError:
        # Recursive but without proper base case
        print("That's not a number! Try again.")
        return get_number(prompt)


def main():
    """The main function that's too long and does too much."""
    calc = Calculator()

    print("Welcome to the Janky Calculator!")
    print("Note: Results may be approximate, confusing, or wrong.")

    while True:
        display_menu()

        try:
            choice = input("Choose (1-9): ").strip()
        except KeyboardInterrupt:
            print("\nWhy'd you interrupt me?")
            sys.exit(1)

        # Messy if-elif chain
        if choice == "1":
            print("\nAddition:")
            a = get_number("First number: ")
            b = get_number("Second number: ")
            result = calc.add(a, b)
            print(f"Result: {result}")

        elif choice == "2":
            print("\nSubtraction (probably):")
            a = get_number("Number to subtract from: ")
            b = get_number("Number to subtract: ")
            result = calc.subtract(a, b)
            print(f"Result: {result}")

        elif choice == "3":
            print("\nMultiplication:")
            a = get_number("First number: ")
            b = get_number("Second number: ")
            result = calc.multiply(a, b)
            print(f"Result: {result}")

        elif choice == "4":
            print("\nDivision (careful!):")
            a = get_number("Numerator: ")
            b = get_number("Denominator: ")
            result = calc.divide(a, b)
            print(f"Result: {result}")

        elif choice == "5":
            print("\nPower:")
            base = get_number("Base: ")
            exp = get_number("Exponent: ")
            result = calc.power(base, exp)
            print(f"Result: {result}")

        elif choice == "6":
            print("\nSquare Root:")
            num = get_number("Number: ")
            if num < 0:
                print("Can't handle imaginary numbers!")
                continue
            result = calc.sqrt(num)
            print(f"Result: {result}")

        elif choice == "7":
            # Buggy memory feature
            global memory
            try:
                value = float(input("Value to store: "))
                memory = value
                calc.CurrentValue = value  # Inconsistent
                print(f"Stored {value} (maybe)")
            except:
                print("Memory storage failed!")

        elif choice == "8":
            # Memory recall
            print(f"Memory contains: {memory}")

        elif choice == "9":
            print("\nGoodbye! Thanks for using this janky calculator!")
            # Unnecessary statistics
            print(f"Operations performed: {operations_count}")
            sys.exit(0)

        else:
            print("Invalid choice! Please try again.")

        # Pause for no good reason
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    # Try-except that catches everything but doesn't handle it well
    try:
        main()
    except Exception as e:
        print(f"A catastrophic error occurred: {e}")
        print("The calculator has given up.")