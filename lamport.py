import tkinter as tk
from tkinter import filedialog, messagebox
from lamport import generate_keys, obfuscate_file, recover_file

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Obfuscation Tool")
        self.geometry("400x300")

        # Key Generation
        self.key_frame = tk.LabelFrame(self, text="Key Management", padx=10, pady=10)
        self.key_frame.pack(pady=10)
        tk.Button(self.key_frame, text="Generate Keys", command=self.generate_keys).pack()

        # File Operations
        self.file_frame = tk.LabelFrame(self, text="File Operations", padx=10, pady=10)
        self.file_frame.pack(pady=10)
        tk.Button(self.file_frame, text="Obfuscate File", command=self.obfuscate).pack(pady=5)
        tk.Button(self.file_frame, text="Recover File", command=self.recover).pack(pady=5)

    def generate_keys(self):
        try:
            generate_keys()
            messagebox.showinfo("Success", "Keys generated successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")

    def obfuscate(self):
        path = filedialog.askopenfilename(title="Select file to obfuscate")
        if not path:
            return
        try:
            output = obfuscate_file(path)
            messagebox.showinfo("Success", f"File obfuscated:\n{output}")
        except Exception as e:
            messagebox.showerror("Error", f"Obfuscation failed: {str(e)}")

    def recover(self):
        path = filedialog.askopenfilename(title="Select file to recover", filetypes=[("Obfuscated", "*.obf")])
        if not path:
            return
        try:
            output = recover_file(path)
            messagebox.showinfo("Success", f"File recovered:\n{output}")
        except Exception as e:
            messagebox.showerror("Error", f"Recovery failed: {str(e)}")

if __name__ == "__main__":
    app = Application()
    app.mainloop()
