import tkinter as tk
from tkinter import messagebox
import math
import random

def linear_congruential_generator(m, a, c, X0, n):
    sequence = []
    Xn = X0
    for _ in range(n):
        Xn = (a * Xn + c) % m
        sequence.append(Xn)
    return sequence


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def cesaro_test(sequence):
    count = 0
    pairs = 0
    for i in range(len(sequence)):
        for j in range(i + 1, len(sequence)):
            pairs += 1
            if gcd(sequence[i], sequence[j]) == 1:
                count += 1
    return count / pairs if pairs > 0 else 0


def find_period(sequence):
    seen = {}
    for idx, number in enumerate(sequence):
        if number in seen:
            return idx - seen[number]
        seen[number] = idx
    return len(sequence)


def generate_sequences():
    try:
        user_input = entry_n.get()
        if not user_input.isdigit():
            raise ValueError("Input must be a positive integer.")

        n = int(user_input)
        if n <= 0:
            raise ValueError("Number must be positive.")

        # Generate sequences
        m = 2 ** 10 - 1  # modulus
        a = 2 ** 5  # multiplier
        c = 0  # increment
        X0 = 2  # initial seed

        custom_sequence = linear_congruential_generator(m, a, c, X0, n)
        random_sequence = [random.randint(0, m - 1) for _ in range(n)]

        result_text = f"Generated sequence (LCG): {custom_sequence}\n\nGenerated sequence (built-in): {random_sequence}"
        messagebox.showinfo("Generated Sequences", result_text)

        with open("custom_random_sequence.txt", "w") as f:
            f.write("Linear Congruential Generator sequence:\n")
            f.write(f"{n}\n")

            for number in custom_sequence:
                f.write(f"{number}\n")

        with open("builtin_random_sequence.txt", "w") as f:
            f.write("Built-in random function sequence:\n")
            f.write(f"{n}\n")

            for number in random_sequence:
                f.write(f"{number}\n")

        period_custom = find_period(custom_sequence)
        probability_custom = cesaro_test(custom_sequence)
        pi_estimate_custom = math.sqrt(6 / probability_custom) if probability_custom != 0 else None

        period_builtin = find_period(random_sequence)
        probability_builtin = cesaro_test(random_sequence)
        pi_estimate_builtin = math.sqrt(6 / probability_builtin) if probability_builtin != 0 else None

        result = (
            f"LCG Period: {period_custom}\n"
            f"Cesaro Probability (LCG): {probability_custom}\n"
            f"Pi Estimate (LCG): {pi_estimate_custom}\n\n"
            f"Built-in Period: {period_builtin}\n"
            f"Cesaro Probability (Built-in): {probability_builtin}\n"
            f"Pi Estimate (Built-in): {pi_estimate_builtin}"
        )

        messagebox.showinfo("Results", result)

    except ValueError as e:
        messagebox.showerror("Error", f"Invalid input: {e}")


root = tk.Tk()
root.title("Random Number Generator")

# UI Elements
label = tk.Label(root, text="Enter the number of random numbers to generate:")
label.pack(pady=10)

entry_n = tk.Entry(root)
entry_n.pack(pady=5)

generate_button = tk.Button(root, text="Generate", command=generate_sequences)
generate_button.pack(pady=10)

root.mainloop()
