import tkinter as tk
from tkinter import messagebox
import json
import os

class User:
    def __init__(self, username, email, password, profile=None):
        if profile is None:
            profile = {}
        self.username = username
        self.email = email
        self.password = password
        self.profile = profile

    def to_dict(self):
        return {
            "username": self.username,
            "password": self.password,
            "profile": self.profile
        }

class UserManager:
    def __init__(self, filename="users.json"):
        self.filename = filename
        self.users = {}
        self.load_users()

    def load_users(self):
        if os.path.exists(self.filename):
            with open(self.filename, "r") as file:
                users_data = json.load(file)
                for email, data in users_data.items():
                    self.users[email] = User(
                        username=data["username"],
                        email=email,
                        password=data["password"],
                        profile=data.get("profile", {})
                    )
        else:
            self.users = {}

    def save_users(self):
        users_data = {email: user.to_dict() for email, user in self.users.items()}
        with open(self.filename, "w") as file:
            json.dump(users_data, file)

    def register_user(self, username, email, password):
        if email in self.users:
            return False, "Email already registered."
        else:
            self.users[email] = User(username, email, password)
            self.save_users()
            return True, "Registration successful."

    def authenticate_user(self, email, password):
        if email in self.users and self.users[email].password == password:
            return True, self.users[email]
        else:
            return False, "Invalid email or password."

    def reset_password(self, email, new_password):
        if email in self.users:
            self.users[email].password = new_password
            self.save_users()
            return True, "Password reset successful."
        else:
            return False, "Email not registered."

    def update_profile(self, email, new_username):
        if email in self.users:
            self.users[email].username = new_username
            self.save_users()
            return True, "Profile updated successfully."
        else:
            return False, "User not found."

class AccountAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Polygon Blockchain Account Analyzer")
        self.geometry("400x300")
        self.current_user = None
        self.user_manager = UserManager()
        self.container = tk.Frame(self)
        self.container.pack(side="top", fill="both", expand=True)
        self.frames = {}
        for F in (LoginScreen, RegisterScreen, ResetPasswordScreen, ProfileScreen):
            frame = F(parent=self.container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame("LoginScreen")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()
    
    def set_current_user(self, user):
        self.current_user = user

    def get_current_user(self):
        return self.current_user

class LoginScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        tk.Label(self, text="Login").pack()
        tk.Label(self, text="Email").pack()
        self.email_entry = tk.Entry(self)
        self.email_entry.pack()
        tk.Label(self, text="Password").pack()
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()
        tk.Button(self, text="Login", command=self.login_user).pack()
        tk.Button(self, text="Register", command=lambda: controller.show_frame("RegisterScreen")).pack()
        tk.Button(self, text="Forgot Password?", command=lambda: controller.show_frame("ResetPasswordScreen")).pack()

    def login_user(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        success, result = self.controller.user_manager.authenticate_user(email, password)
        if success:
            self.controller.set_current_user(result)
            messagebox.showinfo("Success", "Login successful.")
            self.controller.show_frame("ProfileScreen")
        else:
            messagebox.showerror("Error", result)

class RegisterScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        tk.Label(self, text="Register").pack()
        tk.Label(self, text="Username").pack()
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()
        tk.Label(self, text="Email").pack()
        self.email_entry = tk.Entry(self)
        self.email_entry.pack()
        tk.Label(self, text="Password").pack()
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()
        tk.Button(self, text="Register", command=self.register_user).pack()
        tk.Button(self, text="Back to Login", command=lambda: controller.show_frame("LoginScreen")).pack()

    def register_user(self):
        username = self.username_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        success, message = self.controller.user_manager.register_user(username, email, password)
        if success:
            messagebox.showinfo("Success", message)
            self.controller.show_frame("LoginScreen")
        else:
            messagebox.showerror("Error", message)

class ResetPasswordScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        tk.Label(self, text="Reset Password").pack()
        tk.Label(self, text="Email").pack()
        self.email_entry = tk.Entry(self)
        self.email_entry.pack()
        tk.Label(self, text="New Password").pack()
        self.new_password_entry = tk.Entry(self, show="*")
        self.new_password_entry.pack()
        tk.Button(self, text="Reset Password", command=self.reset_password).pack()
        tk.Button(self, text="Back to Login", command=lambda: controller.show_frame("LoginScreen")).pack()

    def reset_password(self):
        email = self.email_entry.get()
        new_password = self.new_password_entry.get()
        success, message = self.controller.user_manager.reset_password(email, new_password)
        if success:
            messagebox.showinfo("Success", message)
            self.controller.show_frame("LoginScreen")
        else:
            messagebox.showerror("Error", message)

class ProfileScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.username_entry = None

    def tkraise(self, *args, **kwargs):
        self.show_profile()
        super().tkraise(*args, **kwargs)

    def show_profile(self):
        self.clear_screen()
        user = self.controller.get_current_user()
        if user is None:
            messagebox.showerror("Error", "No user logged in.")
            self.controller.show_frame("LoginScreen")
            return
        tk.Label(self, text=f"Welcome, {user.username}").pack()
        tk.Label(self, text="Profile Information").pack()
        tk.Label(self, text="Username").pack()
        self.username_entry = tk.Entry(self)
        self.username_entry.insert(0, user.username)
        self.username_entry.pack()
        tk.Button(self, text="Update Profile", command=self.update_profile).pack()
        tk.Button(self, text="Logout", command=self.logout_user).pack()

    def update_profile(self):
        new_username = self.username_entry.get()
        email = self.controller.get_current_user().email
        success, message = self.controller.user_manager.update_profile(email, new_username)
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)

    def logout_user(self):
        self.controller.set_current_user(None)
        messagebox.showinfo("Success", "Logged out successfully.")
        self.controller.show_frame("LoginScreen")

    def clear_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    app = AccountAnalyzerApp()
    app.mainloop()
