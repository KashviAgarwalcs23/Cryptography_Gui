# 🛡️ Cryptography GUI: Lamport One-Time Signature Scheme

This project implements a **cryptographic GUI tool** that enables users to **generate keys**, **sign messages**, and **verify signatures** using the **Lamport One-Time Signature (OTS) scheme**. It provides an intuitive interface to explore fundamental cryptographic principles with a focus on quantum-resistant signatures.

## 📌 Project Highlights

- ✔️ Implementation of Lamport's One-Time Signature scheme (in Python and C)
- ✔️ GUI for signing and verifying files
- ✔️ Sample text files for testing
- ✔️ Educational tool to learn post-quantum cryptography

---

## 🔐 What is Lamport's Signature?

Lamport One-Time Signatures are:
- **Hash-based digital signatures**
- **Quantum-resistant**, unlike RSA or ECC
- Best used **once per key pair** due to their one-time nature

> Reference: [Wikipedia - Lamport Signature](https://en.wikipedia.org/wiki/Lamport_signature)

---

## 🗂️ Folder Structure
Cryptography_Gui/
│
├── lamport.py # Python implementation of Lamport OTS
├── lamport.c # C implementation (for comparison)
├── main.py # GUI application
├── description.txt # Additional project description
├── README.md # Project documentation
│
├── the most distant way in the world.txt
├── stream of life.txt
├── If i die in a war zone.txt # Sample text files for testing

---

## 🖥️ Features

- **Key Generation**  
  Random 256-bit keys for 256-bit messages using SHA-256.

- **Signing Function**  
  Generates a signature by revealing parts of the private key based on the hashed message.

- **Verification Function**  
  Confirms the message’s authenticity using the public key and the signature.

- **GUI Interface**  
  Easy-to-use interface to:
  - Input messages from text files
  - Generate keys
  - Sign messages
  - Verify signatures

---

## 🚀 Getting Started

### 🔧 Requirements

- Python 3.7+
- Tkinter (for GUI)
- GCC (if compiling `lamport.c`)

### ▶️ Run the App

```bash
# Clone the repository
git clone https://github.com/KashviAgarwalcs23/Cryptography_Gui.git
cd Cryptography_Gui

# Run the GUI app
python main.py

📚 Sample Test Files
If i die in a war zone.txt

stream of life.txt

the most distant way in the world.txt

These text files can be used as input messages for signing and verifying.

📈 Future Improvements
Support for multiple signature schemes (RSA, ECDSA)

File encryption/decryption tools

Persistent key storage

Advanced error handling and logging

📜 License
This project is open source and available under the MIT License.

👩‍💻 Author
Kashvi Agarwal
GitHub: @KashviAgarwalcs23

📎 References
Lamport Signatures (Wikipedia)

Post-Quantum Cryptography (NIST)



---

Let me know if you'd like to add screenshots or GIFs of the GUI, or if you want the README tailored for a more academic or professional audience.

