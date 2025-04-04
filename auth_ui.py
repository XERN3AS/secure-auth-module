import customtkinter as ctk
from tkinter import messagebox
import subprocess
import pyotp
import os

# ========== CONFIG ========== #
SECRET_KEY = "JBSWY3DPEHPK3PXP"  # Replace with secure per-user key
exe_path = os.path.abspath(os.path.join(os.getcwd(), "core", "auth_core.exe"))

totp = pyotp.TOTP(SECRET_KEY)
print(f"Generated OTP (debug): {totp.now()}")  # Remove this line in production

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# ========== FUNCTIONS ========== #
def login():
    username = entry_user.get()
    password = entry_pass.get()
    status_label.configure(text="Authenticating...", text_color="orange")

    if not os.path.exists(exe_path):
        messagebox.showerror("Error", f"auth_core.exe not found at:\n{exe_path}")
        return

    try:
        result = subprocess.run(
            [exe_path, username, password],
            capture_output=True,
            text=True,
            shell=True,
            check=False
        )

        if result.returncode == 0:
            verify_otp()
        else:
            error_msg = result.stdout.strip() or result.stderr.strip() or "Unknown error"
            messagebox.showerror("Login Failed", error_msg)
            status_label.configure(text="Login failed ❌", text_color="red")
    except FileNotFoundError:
        messagebox.showerror("Error", "Authentication core executable not found.")
        status_label.configure(text="Executable not found ❌", text_color="red")

def verify_otp():
    otp_window = ctk.CTkToplevel(root)
    otp_window.title("OTP Verification")
    otp_window.geometry("300x170")
    otp_window.grab_set()

    ctk.CTkLabel(otp_window, text="Enter OTP from your authenticator app:").pack(pady=(10, 5))
    otp_entry = ctk.CTkEntry(otp_window)
    otp_entry.pack(pady=5)

    def check_otp():
        user_otp = otp_entry.get()
        expected_otp = totp.now()

        if totp.verify(user_otp, valid_window=1):
            messagebox.showinfo("Success", "Multi-Factor Authentication Passed ✅")
            status_label.configure(text="Access Granted ✅", text_color="green")
            otp_window.destroy()
            open_secure_module()
        else:
            messagebox.showerror("Error", f"Invalid OTP ❌")
            status_label.configure(text="Invalid OTP ❌", text_color="red")

    ctk.CTkButton(otp_window, text="Verify OTP", command=check_otp).pack(pady=10)

def open_secure_module():
    secure_window = ctk.CTkToplevel(root)
    secure_window.title("🔐 Secure Module Access")
    secure_window.geometry("450x300")
    secure_window.grab_set()

    ctk.CTkLabel(
        secure_window,
        text="Welcome to the Secure Module Panel 🛡",
        font=("Arial", 16, "bold")
    ).pack(pady=20)

    ctk.CTkLabel(
        secure_window,
        text="You are now fully authenticated.\nThis is a placeholder for secure tools, settings, or dashboards.",
        font=("Arial", 13),
        wraplength=400,
        justify="center"
    ).pack(pady=10)

    ctk.CTkButton(secure_window, text="Log Out / Close", command=secure_window.destroy).pack(pady=25)

def toggle_password():
    if entry_pass.cget("show") == "*":
        entry_pass.configure(show="")
        show_pass_button.configure(text="Hide Password")
    else:
        entry_pass.configure(show="*")
        show_pass_button.configure(text="Show Password")

# ========== UI SETUP ========== #
root = ctk.CTk()
root.title("🔐 Secure Authentication Module")
root.geometry("400x350")
root.resizable(False, False)

ctk.CTkLabel(root, text="Login", font=("Arial", 20, "bold")).pack(pady=(20, 10))

# Username
ctk.CTkLabel(root, text="Username:").pack(pady=(10, 2))
entry_user = ctk.CTkEntry(root, width=250)
entry_user.pack()

# Password
ctk.CTkLabel(root, text="Password:").pack(pady=(10, 2))
entry_pass = ctk.CTkEntry(root, show="*", width=250)
entry_pass.pack()

# Toggle password visibility
show_pass_button = ctk.CTkButton(root, text="Show Password", command=toggle_password, width=140)
show_pass_button.pack(pady=8)

# Login button
ctk.CTkButton(root, text="Login", command=login, width=160).pack(pady=15)

# Status label
status_label = ctk.CTkLabel(root, text="", font=("Arial", 12))
status_label.pack(pady=5)

# Start loop
root.mainloop()
