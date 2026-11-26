
import tkinter as tk
from tkinter import messagebox
import time

from rsa_secure import encrypt, decrypt, sms_segments
from key_manager import load_public_key, load_private_key


# Interface Colors
BG = "#0f172a"
PANEL = "#1e293b"
TEXT = "#f8fafc"
MUTED = "#94a3b8"
BLUE = "#2563eb"
GREEN = "#15803d"
LIGHT_GREEN = "#4ade80"


class SecureSMSApp:

    def __init__(self, root):

        self.root = root
        self.root.title("RSA Secure SMS")
        self.root.geometry("1050x800")
        self.root.minsize(850, 650)
        self.root.configure(bg=BG)

        self.users = {}

        # Main Title
        tk.Label(
            root,
            text="RSA SECURE SMS",
            font=("Segoe UI", 26, "bold"),
            bg=BG,
            fg=TEXT
        ).pack(pady=(15, 0))

        tk.Label(
            root,
            text="LIS4062 - Information Security",
            font=("Segoe UI", 11),
            bg=BG,
            fg=MUTED
        ).pack()

        tk.Label(
            root,
            text="RSA-OAEP | SHA-256 | Base64",
            font=("Segoe UI", 11),
            bg=BG,
            fg="#60a5fa"
        ).pack(pady=5)

        # User Panels
        container = tk.Frame(root, bg=BG)
        container.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=10
        )

        self.create_panel(container, "alice", BLUE)
        self.create_panel(container, "bob", GREEN)

        # Performance Monitor
        monitor = tk.Frame(root, bg=PANEL)
        monitor.pack(fill="x", padx=15, pady=5)

        tk.Label(
            monitor,
            text="PERFORMANCE MONITOR",
            font=("Segoe UI", 12, "bold"),
            bg=PANEL,
            fg=TEXT
        ).pack(pady=5)

        metrics = tk.Frame(monitor, bg=PANEL)
        metrics.pack(fill="x")

        self.enc_time = tk.StringVar(value="--- ms")
        self.dec_time = tk.StringVar(value="--- ms")
        self.cipher_length = tk.StringVar(value="---")
        self.segments = tk.StringVar(value="---")

        self.create_metric(
            metrics, "Encryption", self.enc_time
        )

        self.create_metric(
            metrics, "Decryption", self.dec_time
        )

        self.create_metric(
            metrics, "Ciphertext length", self.cipher_length
        )

        self.create_metric(
            metrics, "SMS segments", self.segments
        )

        # Status Bar
        self.status = tk.StringVar(
            value="System ready. SMS channel simulated."
        )

        tk.Label(
            root,
            textvariable=self.status,
            bg=BG,
            fg=LIGHT_GREEN,
            font=("Segoe UI", 10)
        ).pack(pady=8)

    # Create Performance Metric
    def create_metric(self, parent, title, variable):

        frame = tk.Frame(parent, bg=PANEL)

        frame.pack(
            side="left",
            expand=True,
            fill="x",
            pady=8
        )

        tk.Label(
            frame,
            text=title,
            bg=PANEL,
            fg=MUTED
        ).pack()

        tk.Label(
            frame,
            textvariable=variable,
            font=("Segoe UI", 16, "bold"),
            bg=PANEL,
            fg=TEXT
        ).pack()

    # Create User Panel
    def create_panel(self, parent, user, color):

        panel = tk.Frame(parent, bg=PANEL)

        panel.pack(
            side="left",
            fill="both",
            expand=True,
            padx=7
        )

        tk.Label(
            panel,
            text=user.upper(),
            font=("Segoe UI", 20, "bold"),
            fg=TEXT,
            bg=PANEL
        ).pack(pady=(10, 0))

        public_key = load_public_key(user)

        tk.Label(
            panel,
            text=f"RSA Key: {public_key.size_in_bits()} bits",
            fg=MUTED,
            bg=PANEL
        ).pack()

        # Original Message
        self.create_label(panel, "Write a message")

        message = self.create_textbox(panel, 4)

        tk.Button(
            panel,
            text="ENCRYPT & SEND",
            command=lambda: self.send_message(user),
            bg=color,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2"
        ).pack(fill="x", padx=12, pady=5)

        # Sent Ciphertext
        self.create_label(panel, "Sent ciphertext (Base64)")

        sent = self.create_textbox(panel, 4)

        tk.Button(
            panel,
            text="COPY CIPHERTEXT",
            command=lambda: self.copy_text(sent),
            bg="#334155",
            fg=TEXT,
            relief="flat"
        ).pack(fill="x", padx=12, pady=4)

        # Received Ciphertext
        self.create_label(
            panel, "Received ciphertext (Base64)"
        )

        received = self.create_textbox(panel, 4)

        # Decrypt Button
        tk.Button(
            panel,
            text="DECRYPT MESSAGE",
            command=lambda: self.receive_message(user),
            bg=color,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2"
        ).pack(fill="x", padx=12, pady=5)

        # Wrong Key Test
        tk.Button(
            panel,
            text="TEST INCORRECT PRIVATE KEY",
            command=lambda: self.test_wrong_key(user),
            bg="#991b1b",
            fg="white",
            relief="flat"
        ).pack(fill="x", padx=12, pady=4)

        # Decrypted Message
        self.create_label(panel, "Decrypted message")

        decrypted = self.create_textbox(panel, 3)

        self.users[user] = {
            "message": message,
            "sent": sent,
            "received": received,
            "decrypted": decrypted
        }

    # Create Section Label
    def create_label(self, parent, text):

        tk.Label(
            parent,
            text=text,
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 10)
        ).pack(anchor="w", padx=12, pady=(6, 2))

    # Create Text Box
    def create_textbox(self, parent, height):

        textbox = tk.Text(
            parent,
            height=height,
            width=40,
            bg=BG,
            fg=TEXT,
            insertbackground="white",
            relief="flat",
            wrap="word",
            font=("Consolas", 10)
        )

        textbox.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=2
        )

        return textbox

    # Update Text Box
    def update_textbox(self, textbox, text):

        textbox.delete("1.0", tk.END)
        textbox.insert("1.0", text)

    # Copy Ciphertext
    def copy_text(self, textbox):

        text = textbox.get("1.0", "end-1c")

        if text:

            self.root.clipboard_clear()
            self.root.clipboard_append(text)

            self.status.set(
                "Ciphertext copied to clipboard."
            )

    # Encrypt and Send Message
    def send_message(self, sender):

        receiver = "bob" if sender == "alice" else "alice"

        message = self.users[sender]["message"].get(
            "1.0", "end-1c"
        )

        if not message:

            messagebox.showwarning(
                "Warning", "Enter a message first."
            )

            return

        public_key = load_public_key(receiver)

        max_bytes = public_key.size_in_bytes() - 66

        if len(message.encode("utf-8")) > max_bytes:

            messagebox.showerror(
                "Error",
                f"Maximum message size: {max_bytes} bytes."
            )

            return

        try:

            start = time.perf_counter()

            ciphertext = encrypt(message, public_key)

            elapsed = (
                time.perf_counter() - start
            ) * 1000

            # Display Sent Ciphertext
            self.update_textbox(
                self.users[sender]["sent"],
                ciphertext
            )

            # Simulated SMS Transmission
            self.update_textbox(
                self.users[receiver]["received"],
                ciphertext
            )

            self.update_textbox(
                self.users[receiver]["decrypted"],
                ""
            )

            # Update Performance Monitor
            self.enc_time.set(f"{elapsed:.4f} ms")
            self.dec_time.set("--- ms")
            self.cipher_length.set(
                f"{len(ciphertext)} chars"
            )

            self.segments.set(
                str(sms_segments(ciphertext))
            )

            self.status.set(
                f"{sender.capitalize()} -> "
                f"{receiver.capitalize()}: "
                "Encrypted message sent (simulation)."
            )

        except ValueError as error:

            messagebox.showerror(
                "Encryption Error",
                str(error)
            )

    # Decrypt Received Message
    def receive_message(self, user):

        ciphertext = self.users[user]["received"].get(
            "1.0", "end-1c"
        ).strip()

        if not ciphertext:

            messagebox.showwarning(
                "Warning",
                "No encrypted message received."
            )

            return

        try:

            private_key = load_private_key(user)

            start = time.perf_counter()

            message = decrypt(ciphertext, private_key)

            elapsed = (
                time.perf_counter() - start
            ) * 1000

            self.update_textbox(
                self.users[user]["decrypted"],
                message
            )

            self.dec_time.set(f"{elapsed:.4f} ms")

            self.cipher_length.set(
                f"{len(ciphertext)} chars"
            )

            self.segments.set(
                str(sms_segments(ciphertext))
            )

            self.status.set(
                f"{user.capitalize()}: "
                "Successful decryption."
            )

        except ValueError:

            self.update_textbox(
                self.users[user]["decrypted"], ""
            )

            messagebox.showerror(
                "Decryption Error",
                "Invalid ciphertext or incorrect private key."
            )

            self.status.set("Decryption failed.")

    # Test Incorrect Private Key
    def test_wrong_key(self, user):

        ciphertext = self.users[user]["received"].get(
            "1.0", "end-1c"
        ).strip()

        if not ciphertext:

            messagebox.showwarning(
                "Warning",
                "Receive an encrypted message first."
            )

            return

        other_user = "bob" if user == "alice" else "alice"

        # Verify ciphertext is valid with the correct key
        try:

            decrypt(
                ciphertext,
                load_private_key(user)
            )

        except ValueError:

            messagebox.showerror(
                "Invalid Test",
                "Ciphertext must first decrypt correctly."
            )

            return

        # Attempt decryption with the incorrect key
        try:

            wrong_key = load_private_key(other_user)

            decrypt(ciphertext, wrong_key)

            messagebox.showerror(
                "Security Test",
                "Security test: FAILED"
            )

        except ValueError:

            messagebox.showinfo(
                "Security Test",
                "Incorrect private key detected.\n"
                "Decryption denied.\n\n"
                "Security test: PASSED"
            )

            self.status.set(
                "Security test: PASSED."
            )


# Main Application
if __name__ == "__main__":

    root = tk.Tk()
    app = SecureSMSApp(root)
    root.mainloop()
