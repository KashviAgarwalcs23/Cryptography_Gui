import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import logging
import lamport

# Set up logging
logging.basicConfig(filename='logs/app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

KEY_DIR = 'keys/'
os.makedirs(KEY_DIR, exist_ok=True)

# Main Application Class
class LamportApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Lamport Signature Tool")
        self.geometry("600x400")
        self.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        tab_control = ttk.Notebook(self)

        # Key Generation Tab
        self.key_gen_tab = ttk.Frame(tab_control)
        tab_control.add(self.key_gen_tab, text='Key Generation')
        self.create_key_gen_tab()

        # File Signing Tab
        self.sign_tab = ttk.Frame(tab_control)
        tab_control.add(self.sign_tab, text='File Signing')
        self.create_sign_tab()

        # Signature Verification Tab
        self.verify_tab = ttk.Frame(tab_control)
        tab_control.add(self.verify_tab, text='Signature Verification')
        self.create_verify_tab()

        tab_control.pack(expand=1, fill='both')

    def create_key_gen_tab(self):
        label = ttk.Label(self.key_gen_tab, text="Generate Key Pairs")
        label.pack(pady=10)
        self.key_gen_button = ttk.Button(self.key_gen_tab, text="Generate Keys", command=self.generate_keys)
        self.key_gen_button.pack(pady=10)

    def create_sign_tab(self):
        label = ttk.Label(self.sign_tab, text="Sign a File")
        label.pack(pady=10)
        self.sign_button = ttk.Button(self.sign_tab, text="Sign File", command=self.sign_file)
        self.sign_button.pack(pady=10)

    def create_verify_tab(self):
        label = ttk.Label(self.verify_tab, text="Verify Signature")
        label.pack(pady=10)
        self.verify_button = ttk.Button(self.verify_tab, text="Verify Signature", command=self.verify_signature)
        self.verify_button.pack(pady=10)

    def generate_keys(self):
        try:
            lamport.generate_keys()
            messagebox.showinfo("Success", "Keys generated successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def sign_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Sign")
        if not file_path:
            return
        try:
            signature_path = lamport.sign_file(file_path)
            messagebox.showinfo("Success", f"File signed successfully!
Signature saved at: {signature_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def verify_signature(self):
        file_path = filedialog.askopenfilename(title="Select File to Verify")
        if not file_path:
            return

        signature_path = filedialog.askopenfilename(title="Select Signature File")
        if not signature_path:
            return

        try:
            is_valid = lamport.verify_signature(file_path, signature_path)
            if is_valid:
                messagebox.showinfo("Verification Successful", "The signature is valid.")
            else:
                messagebox.showwarning("Verification Failed", "The signature is invalid.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = LamportApp()
    app.mainloop()
