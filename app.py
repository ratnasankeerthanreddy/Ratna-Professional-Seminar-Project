import tkinter as tk
from tkinter import messagebox
import json
import os

class AccountAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Polygon Blockchain Account Analyzer")
        self.root.geometry("400x300")
        self.current_user = None
        self.load_users()
        self.show_login_screen()

    def load_users(self):
        if os.path.exists("users.json"):
            with open("users.json", "r") as file:
                self.users = json.load(file)
        else:
            self.users = {}

    def save_users(self):
        with open("users.json", "w") as file:
            json.dump(self.users, file)

    def show_register_screen(self):
        self.clear_screen()
        tk.Label(self.root, text="Register").pack()
        tk.Label(self.root, text="Username").pack()
        username_entry = tk.Entry(self.root)
        username_entry.pack()
        tk.Label(self.root, text="Email").pack()
        email_entry = tk.Entry(self.root)
        email_entry.pack()
        tk.Label(self.root, text="Password").pack()
        password_entry = tk.Entry(self.root, show="*")
        password_entry.pack()
        tk.Button(self.root, text="Register", command=lambda: self.register_user(username_entry.get(), email_entry.get(), password_entry.get())).pack()
        tk.Button(self.root, text="Back to Login", command=self.show_login_screen).pack()

    def register_user(self, username, email, password):
        if email in self.users:
            messagebox.showerror("Error", "Email already registered.")
        else:
            self.users[email] = {"username": username, "password": password, "profile": {}}
            self.save_users()
            messagebox.showinfo("Success", "Registration successful.")
            self.show_login_screen()

    def show_login_screen(self):
        self.clear_screen()
        tk.Label(self.root, text="Login").pack()
        tk.Label(self.root, text="Email").pack()
        email_entry = tk.Entry(self.root)
        email_entry.pack()
        tk.Label(self.root, text="Password").pack()
        password_entry = tk.Entry(self.root, show="*")
        password_entry.pack()
        tk.Button(self.root, text="Login", command=lambda: self.login_user(email_entry.get(), password_entry.get())).pack()
        tk.Button(self.root, text="Register", command=self.show_register_screen).pack()

    def login_user(self, email, password):
        if email in self.users and self.users[email]["password"] == password:
            self.current_user = email
            messagebox.showinfo("Success", "Login successful.")
            self.show_profile_screen()
        else:
            messagebox.showerror("Error", "Invalid email or password.")

    def logout_user(self):
        self.current_user = None
        messagebox.showinfo("Success", "Logged out successfully.")
        self.show_login_screen()

    def show_reset_password_screen(self):
        self.clear_screen()
        tk.Label(self.root, text="Reset Password").pack()
        tk.Label(self.root, text="Email").pack()
        email_entry = tk.Entry(self.root)
        email_entry.pack()
        tk.Label(self.root, text="New Password").pack()
        new_password_entry = tk.Entry(self.root, show="*")
        new_password_entry.pack()
        tk.Button(self.root, text="Reset Password", command=lambda: self.reset_password(email_entry.get(), new_password_entry.get())).pack()
        tk.Button(self.root, text="Back to Login", command=self.show_login_screen).pack()

    def reset_password(self, email, new_password):
        if email in self.users:
            self.users[email]["password"] = new_password
            self.save_users()
            messagebox.showinfo("Success", "Password reset successful.")
            self.show_login_screen()
        else:
            messagebox.showerror("Error", "Email not registered.")

    def show_profile_screen(self):
        self.clear_screen()
        user_data = self.users[self.current_user]
        tk.Label(self.root, text=f"Welcome, {user_data['username']}").pack()
        tk.Label(self.root, text="Profile Information").pack()
        tk.Label(self.root, text="Username").pack()
        username_entry = tk.Entry(self.root)
        username_entry.insert(0, user_data["username"])
        username_entry.pack()
        tk.Button(self.root, text="Update Profile", command=lambda: self.update_profile(username_entry.get())).pack()
        tk.Button(self.root, text="Logout", command=self.logout_user).pack()

    def update_profile(self, new_username):
        self.users[self.current_user]["username"] = new_username
        self.save_users()
        messagebox.showinfo("Success", "Profile updated successfully.")

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = AccountAnalyzerApp(root)
    root.mainloop()

