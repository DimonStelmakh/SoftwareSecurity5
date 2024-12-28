import tkinter as tk
from tkinter import messagebox, filedialog
import random
from math import gcd
import base64
import hashlib


class RSADigitalSignature:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Система ЕЦП RSA")
        self.window.geometry("800x700")

        # змінні для зберігання ключів
        self.public_key = None  # e, n
        self.private_key = None  # d, n
        self.p = None
        self.q = None

        self.create_widgets()

    def create_widgets(self):
        key_frame = tk.LabelFrame(self.window, text="1. Генерація ключів", padx=5, pady=5)
        key_frame.pack(padx=10, pady=5, fill="x")

        key_size_frame = tk.Frame(key_frame)
        key_size_frame.pack(pady=5)

        tk.Label(key_size_frame, text="Розмір ключа (біт):").pack(side=tk.LEFT)
        self.key_size_var = tk.StringVar(value="1024")
        tk.Entry(key_size_frame, textvariable=self.key_size_var, width=10).pack(side=tk.LEFT, padx=5)

        tk.Button(key_frame, text="Згенерувати нову пару ключів", command=self.generate_keys).pack(pady=5)

        self.key_display = tk.Text(key_frame, height=6, width=70)
        self.key_display.pack(pady=5)

        sign_frame = tk.LabelFrame(self.window, text="2. Підписування повідомлення (використання закритого ключа)",
                                   padx=5, pady=5)
        sign_frame.pack(padx=10, pady=5, fill="x")

        tk.Label(sign_frame, text="Введіть повідомлення для підписування:").pack()
        self.sign_input = tk.Entry(sign_frame, width=70)
        self.sign_input.pack(pady=5)

        button_frame = tk.Frame(sign_frame)
        button_frame.pack(fill="x", pady=5)

        button_center_frame = tk.Frame(button_frame)
        button_center_frame.pack(expand=True)

        tk.Button(button_center_frame, text="Вибрати файл", command=self.select_file_to_sign).pack(side=tk.LEFT, padx=5)
        tk.Button(button_center_frame, text="Підписати повідомлення", command=self.sign_message).pack(side=tk.LEFT)

        self.sign_output = tk.Text(sign_frame, height=4, width=70)
        self.sign_output.pack(pady=5)

        verify_frame = tk.LabelFrame(self.window, text="3. Перевірка підпису (використання відкритого ключа)",
                                     padx=5, pady=5)
        verify_frame.pack(padx=10, pady=5, fill="x")

        tk.Label(verify_frame, text="Оригінальне повідомлення:").pack()
        self.verify_message_input = tk.Entry(verify_frame, width=70)
        self.verify_message_input.pack(pady=5)

        tk.Label(verify_frame, text="Цифровий підпис:").pack()
        self.verify_signature_input = tk.Text(verify_frame, height=4, width=70)
        self.verify_signature_input.pack(pady=5)

        button_frame = tk.Frame(verify_frame)
        button_frame.pack(fill="x", pady=5)

        button_center_frame = tk.Frame(button_frame)
        button_center_frame.pack(expand=True)

        tk.Button(button_center_frame, text="Вибрати файл", command=self.select_file_to_verify).pack(side=tk.LEFT,
                                                                                                     padx=5)
        tk.Button(button_center_frame, text="Перевірити підпис", command=self.verify_signature).pack(side=tk.LEFT)

        self.verify_result = tk.Text(verify_frame, height=2, width=70)
        self.verify_result.pack(pady=5)

    def is_prime(self, n, k=5):
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime(self, bits):
        while True:
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1
            if self.is_prime(n):
                return n

    def mod_inverse(self, e, phi):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        _, x, _ = extended_gcd(e, phi)
        return (x % phi + phi) % phi

    def generate_keys(self):
        try:
            key_size = int(self.key_size_var.get())
            if key_size < 512:
                messagebox.showerror("Помилка", "Розмір ключа має бути не менше 512 біт")
                return

            self.p = self.generate_prime(key_size // 2)
            self.q = self.generate_prime(key_size // 2)
            n = self.p * self.q
            phi = (self.p - 1) * (self.q - 1)
            e = 65537
            d = self.mod_inverse(e, phi)

            self.public_key = (e, n)
            self.private_key = (d, n)

            self.key_display.delete(1.0, tk.END)
            self.key_display.insert(tk.END, f"Відкритий ключ (e, n):\n{self.public_key}\n\n")
            self.key_display.insert(tk.END, f"Закритий ключ (d, n):\n{self.private_key}\n")

            messagebox.showinfo("Успіх", "Ключі успішно згенеровано!")

        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка при генерації ключів: {str(e)}")

    def calculate_hash(self, message):
        # обчислюємо хеш-значення
        return int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')

    def sign_message(self):
        if not self.private_key:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключі!")
            return

        try:
            message = self.sign_input.get()
            if not message:
                messagebox.showerror("Помилка", "Введіть повідомлення для підписування!")
                return

            # обчислюємо хеш повідомлення
            message_hash = self.calculate_hash(message)

            # підписуємо хеш за допомогою закритого ключа
            d, n = self.private_key
            signature = pow(message_hash, d, n)

            # конвертуємо підпис у base64
            signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, 'big')
            signature_base64 = base64.b64encode(signature_bytes).decode()

            self.sign_output.delete(1.0, tk.END)
            self.sign_output.insert(tk.END, signature_base64)

            messagebox.showinfo("Успіх", "Повідомлення успішно підписано!")

        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка при підписуванні: {str(e)}")

    def verify_signature(self):
        if not self.public_key:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключі!")
            return

        try:
            message = self.verify_message_input.get()
            signature_base64 = self.verify_signature_input.get(1.0, tk.END).strip()

            if not message or not signature_base64:
                messagebox.showerror("Помилка", "Введіть повідомлення та підпис!")
                return

            # перетворюємо підпис назад у число
            signature_bytes = base64.b64decode(signature_base64)
            signature = int.from_bytes(signature_bytes, 'big')

            # обчислюємо хеш оригінального повідомлення
            message_hash = self.calculate_hash(message)

            # перевіряємо підпис за допомогою відкритого ключа
            e, n = self.public_key
            decrypted_hash = pow(signature, e, n)

            # порівнюємо хеші
            is_valid = (decrypted_hash == message_hash)

            self.verify_result.delete(1.0, tk.END)
            if is_valid:
                self.verify_result.insert(tk.END, "Підпис дійсний ✓")
                self.verify_result.configure(fg="green")
            else:
                self.verify_result.insert(tk.END, "Підпис недійсний ✗")
                self.verify_result.configure(fg="red")

        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка при перевірці підпису: {str(e)}")

    def select_file_to_sign(self):
        filename = filedialog.askopenfilename()
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as file:
                    content = file.read()
                    self.sign_input.delete(0, tk.END)
                    self.sign_input.insert(0, content)
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка при читанні файлу: {str(e)}")

    def select_file_to_verify(self):
        filename = filedialog.askopenfilename()
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as file:
                    content = file.read()
                    self.verify_message_input.delete(0, tk.END)
                    self.verify_message_input.insert(0, content)
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка при читанні файлу: {str(e)}")

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = RSADigitalSignature()
    app.run()