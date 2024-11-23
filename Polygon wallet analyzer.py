import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import os
import requests
import datetime
from tkinter import ttk
import threading
import pandas as pd 

# ---------------------------- User Management ---------------------------- #

class User:
    def __init__(self, username, email, password, profile=None, wallets=None):
        if profile is None:
            profile = {}
        if wallets is None:
            wallets = []
        self.username = username
        self.email = email
        self.password = password
        self.profile = profile
        self.wallets = wallets

    def to_dict(self):
        return {
            "username": self.username,
            "password": self.password,
            "profile": self.profile,
            "wallets": self.wallets
        }

class UserManager:
    def __init__(self, filename="users.json"):
        self.filename = filename
        self.users = {}
        self.load_users()

    def load_users(self):
        if os.path.exists(self.filename):
            with open(self.filename, "r") as file:
                try:
                    users_data = json.load(file)
                    for email, data in users_data.items():
                        self.users[email] = User(
                            username=data["username"],
                            email=email,
                            password=data["password"],
                            profile=data.get("profile", {}),
                            wallets=data.get("wallets", [])
                        )
                except json.JSONDecodeError:
                    messagebox.showerror("Error", "Failed to decode users.json. The file might be corrupted.")
                    self.users = {}
        else:
            self.users = {}

    def save_users(self):
        users_data = {email: user.to_dict() for email, user in self.users.items()}
        with open(self.filename, "w") as file:
            json.dump(users_data, file, indent=4)

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
            return True, "Profile name updated successfully."
        else:
            return False, "User not found."

    # ---------------------------- Wallet Management ---------------------------- #

    def add_wallet(self, email, wallet_address):
        if email in self.users:
            user = self.users[email]
            if wallet_address not in user.wallets:
                user.wallets.append(wallet_address)
                self.save_users()
                return True, "Wallet added successfully."
            else:
                return False, "Wallet address already exists."
        return False, "User not found."

    def remove_wallet(self, email, wallet_address):
        if email in self.users:
            user = self.users[email]
            if wallet_address in user.wallets:
                user.wallets.remove(wallet_address)
                self.save_users()
                return True, "Wallet removed successfully."
            else:
                return False, "Wallet address not found."
        return False, "User not found."

    def get_wallets(self, email):
        if email in self.users:
            return self.users[email].wallets
        return []

    # ---------------------------- Change Password Method ---------------------------- #

    def change_password(self, email, current_password, new_password):
        if email in self.users:
            user = self.users[email]
            if user.password == current_password:
                user.password = new_password
                self.save_users()
                return True, "Password updated successfully."
            else:
                return False, "Current password is incorrect."
        return False, "User not found."

# ---------------------------- PolygonScan API Integration ---------------------------- #

class PolygonWallet:
    API_KEY = "9EE21IJ1HQYDRY2WD3VJGBRUIJ88CD1FA9"  # Replace with your actual API key

    @staticmethod
    def get_wallet_balance(address):
        url = "https://api.polygonscan.com/api"
        params = {
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest",
            "apikey": PolygonWallet.API_KEY
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "1":
                balance_wei = int(data["result"])
                balance_matic = balance_wei / (10 ** 18)  # Convert Wei to MATIC
                return balance_matic
            else:
                return None
        except requests.RequestException as e:
            print(f"Error fetching balance for {address}: {e}")
            return None

    @staticmethod
    def get_wallet_transactions(address):
        url = "https://api.polygonscan.com/api"
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "page": 1,
            "offset": 9999,
            "sort": "asc",
            "apikey": PolygonWallet.API_KEY
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "1":
                return data.get("result", [])
            else:
                return []
        except requests.RequestException as e:
            print(f"Error fetching transactions for {address}: {e}")
            return []

    @staticmethod
    def get_erc20_token_transfer(tx_hash):
        url = "https://api.polygonscan.com/api"
        params = {
            "module": "account",
            "action": "tokentx",
            "txhash": tx_hash,
            "apikey": PolygonWallet.API_KEY
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "1":
                return data.get("result", [])
            else:
                return []
        except requests.RequestException as e:
            print(f"Error fetching ERC-20 transfers for {tx_hash}: {e}")
            return []

    @staticmethod
    def get_erc721_token_transfer(tx_hash):
        url = "https://api.polygonscan.com/api"
        params = {
            "module": "account",
            "action": "tokennfttx",
            "txhash": tx_hash,
            "apikey": PolygonWallet.API_KEY
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "1":
                return data.get("result", [])
            else:
                return []
        except requests.RequestException as e:
            print(f"Error fetching ERC-721 transfers for {tx_hash}: {e}")
            return []

    # Added Methods for New Functionality

    @staticmethod
    def get_erc20_token_transfers(address):
        url = "https://api.polygonscan.com/api"
        params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "asc",
            "apikey": PolygonWallet.API_KEY
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "1":
                return data.get("result", [])
            else:
                return []
        except requests.RequestException as e:
            print(f"Error fetching ERC-20 transfers for {address}: {e}")
            return []

    @staticmethod
    def get_erc721_token_transfers(address):
        url = "https://api.polygonscan.com/api"
        params = {
            "module": "account",
            "action": "tokennfttx",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "asc",
            "apikey": PolygonWallet.API_KEY
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "1":
                return data.get("result", [])
            else:
                return []
        except requests.RequestException as e:
            print(f"Error fetching ERC-721 transfers for {address}: {e}")
            return []

    @staticmethod
    def get_erc20_token_balances(address):
        url = "https://api.polygonscan.com/api"
        params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "asc",
            "apikey": PolygonWallet.API_KEY
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "1":
                transfers = data.get("result", [])
                balances = {}
                for transfer in transfers:
                    token_symbol = transfer['tokenSymbol']
                    token_decimals = int(transfer['tokenDecimal'])
                    value = int(transfer['value']) / (10 ** token_decimals)
                    if transfer['to'].lower() == address.lower():
                        balances[token_symbol] = balances.get(token_symbol, 0) + value
                    elif transfer['from'].lower() == address.lower():
                        balances[token_symbol] = balances.get(token_symbol, 0) - value
                # Remove tokens with zero balance
                balances = {k: v for k, v in balances.items() if v > 0}
                return balances
            else:
                return None
        except requests.RequestException as e:
            print(f"Error fetching ERC-20 balances for {address}: {e}")
            return None

    @staticmethod
    def get_erc721_tokens(address):
        url = "https://api.polygonscan.com/api"
        params = {
            "module": "account",
            "action": "tokennfttx",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "asc",
            "apikey": PolygonWallet.API_KEY
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "1":
                transfers = data.get("result", [])
                tokens = {}
                for transfer in transfers:
                    token_name = transfer['tokenName']
                    token_id = transfer['tokenID']
                    if transfer['to'].lower() == address.lower():
                        tokens[token_name] = tokens.get(token_name, set())
                        tokens[token_name].add(token_id)
                    elif transfer['from'].lower() == address.lower():
                        if token_name in tokens and token_id in tokens[token_name]:
                            tokens[token_name].remove(token_id)
                # Remove empty token sets
                tokens = {k: v for k, v in tokens.items() if v}
                return tokens
            else:
                return None
        except requests.RequestException as e:
            print(f"Error fetching ERC-721 tokens for {address}: {e}")
            return None

    @staticmethod
    def get_matic_price_in_usd():
        url = "https://api.coingecko.com/api/v3/simple/price"
        params = {
            "ids": "matic-network",
            "vs_currencies": "usd"
        }
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            price = data.get("matic-network", {}).get("usd", None)
            return price
        except requests.RequestException as e:
            print(f"Error fetching MATIC price in USD: {e}")
            return None

    @staticmethod
    def get_token_prices_in_matic(tokens):
        # For simplicity, we will assume tokens have zero value.
        # Implement API calls to get real-time token prices as needed.
        prices = {token: 0 for token in tokens}
        return prices

# ---------------------------- Application GUI ---------------------------- #

class AccountAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Polygon Blockchain Account Analyzer")
        self.geometry("700x700")  # Adjusted size for added data fetching section
        self.current_user = None
        self.user_manager = UserManager()
        self.container = tk.Frame(self)
        self.container.pack(side="top", fill="both", expand=True)
        self.frames = {}
        # Add all necessary frames
        for F in (LoginScreen, RegisterScreen, ResetPasswordScreen, ProfileScreen, WalletTransactionScreen):
            frame = F(parent=self.container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame("LoginScreen")

    def show_frame(self, page_name):
        frame = self.frames.get(page_name)
        if frame:
            frame.tkraise()
        else:
            messagebox.showerror("Error", f"Page '{page_name}' does not exist.")

    def set_current_user(self, user):
        self.current_user = user

    def get_current_user(self):
        return self.current_user

# ---------------------------- Login Screen ---------------------------- #

class LoginScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        # Create a frame to center the widgets
        frame = tk.Frame(self)
        frame.pack(expand=True)

        tk.Label(frame, text="Login", font=("Helvetica", 18)).pack(pady=20)

        tk.Label(frame, text="Email", font=("Helvetica", 14)).pack(pady=(10, 5))
        self.email_entry = tk.Entry(frame, width=50, font=("Helvetica", 14))
        self.email_entry.pack()

        tk.Label(frame, text="Password", font=("Helvetica", 14)).pack(pady=(10, 5))
        self.password_entry = tk.Entry(frame, show="*", width=50, font=("Helvetica", 14))
        self.password_entry.pack()

        self.login_btn = tk.Button(frame, text="Login", width=25, font=("Helvetica", 14), command=self.login_user)
        self.login_btn.pack(pady=15)

        self.register_btn = tk.Button(frame, text="Register", width=25, font=("Helvetica", 14), command=lambda: self.controller.show_frame("RegisterScreen"))
        self.register_btn.pack(pady=5)

        self.forgot_password_btn = tk.Button(frame, text="Forgot Password?", width=25, font=("Helvetica", 14), command=lambda: self.controller.show_frame("ResetPasswordScreen"))
        self.forgot_password_btn.pack(pady=10)

    def login_user(self):
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        if not email or not password:
            messagebox.showerror("Error", "Please enter both email and password.")
            return
        success, result = self.controller.user_manager.authenticate_user(email, password)
        if success:
            self.controller.set_current_user(result)
            messagebox.showinfo("Success", "Login successful.")
            self.controller.show_frame("ProfileScreen")
            self.clear_entries()
        else:
            messagebox.showerror("Error", result)

    def clear_entries(self):
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

# ---------------------------- Register Screen ---------------------------- #

class RegisterScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        # Create a frame to center the widgets
        frame = tk.Frame(self)
        frame.pack(expand=True)

        tk.Label(frame, text="Register", font=("Helvetica", 24)).pack(pady=20)

        tk.Label(frame, text="Username", font=("Helvetica", 14)).pack(pady=(20, 5))
        self.username_entry = tk.Entry(frame, width=50, font=("Helvetica", 14))
        self.username_entry.pack()

        tk.Label(frame, text="Email", font=("Helvetica", 14)).pack(pady=(20, 5))
        self.email_entry = tk.Entry(frame, width=50, font=("Helvetica", 14))
        self.email_entry.pack()

        tk.Label(frame, text="Password", font=("Helvetica", 14)).pack(pady=(20, 5))
        self.password_entry = tk.Entry(frame, show="*", width=50, font=("Helvetica", 14))
        self.password_entry.pack()

        self.register_btn = tk.Button(frame, text="Register", width=25, font=("Helvetica", 14), command=self.register_user)
        self.register_btn.pack(pady=30)

        self.back_to_login_btn = tk.Button(frame, text="Back to Login", width=25, font=("Helvetica", 14), command=lambda: self.controller.show_frame("LoginScreen"))
        self.back_to_login_btn.pack(pady=5)

    def register_user(self):
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not email or not password:
            messagebox.showerror("Error", "Please fill out all fields.")
            return
        success, message = self.controller.user_manager.register_user(username, email, password)
        if success:
            messagebox.showinfo("Success", message)
            self.controller.show_frame("LoginScreen")
            self.clear_entries()
        else:
            messagebox.showerror("Error", message)

    def clear_entries(self):
        self.username_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

# ---------------------------- Reset Password Screen ---------------------------- #

class ResetPasswordScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        # Create a frame to center the widgets
        frame = tk.Frame(self)
        frame.pack(expand=True)

        tk.Label(frame, text="Reset Password", font=("Helvetica", 24)).pack(pady=20)

        tk.Label(frame, text="Email", font=("Helvetica", 14)).pack(pady=(20, 5))
        self.email_entry = tk.Entry(frame, width=50, font=("Helvetica", 14))
        self.email_entry.pack()

        tk.Label(frame, text="New Password", font=("Helvetica", 14)).pack(pady=(20, 5))
        self.new_password_entry = tk.Entry(frame, show="*", width=50, font=("Helvetica", 14))
        self.new_password_entry.pack()

        self.reset_password_btn = tk.Button(frame, text="Reset Password", width=25, font=("Helvetica", 14), command=self.reset_password)
        self.reset_password_btn.pack(pady=30)

        self.back_to_login_btn = tk.Button(frame, text="Back to Login", width=25, font=("Helvetica", 14), command=lambda: self.controller.show_frame("LoginScreen"))
        self.back_to_login_btn.pack(pady=5)

    def reset_password(self):
        email = self.email_entry.get().strip()
        new_password = self.new_password_entry.get().strip()
        if not email or not new_password:
            messagebox.showerror("Error", "Please enter both email and new password.")
            return
        success, message = self.controller.user_manager.reset_password(email, new_password)
        if success:
            messagebox.showinfo("Success", message)
            self.controller.show_frame("LoginScreen")
            self.clear_entries()
        else:
            messagebox.showerror("Error", message)

    def clear_entries(self):
        self.email_entry.delete(0, tk.END)
        self.new_password_entry.delete(0, tk.END)

# ---------------------------- Profile Screen ---------------------------- #

class ProfileScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.username_entry = None
        self.create_widgets()

    def create_widgets(self):
        # Create a frame to center the widgets
        frame = tk.Frame(self)
        frame.pack(expand=True)

        self.header_label = tk.Label(frame, text="", font=("Helvetica", 24))
        self.header_label.pack(pady=20)

        tk.Label(frame, text="Profile Information", font=("Helvetica", 16)).pack(pady=10)

        tk.Label(frame, text="Username", font=("Helvetica", 14)).pack(pady=(10, 5))
        self.username_entry = tk.Entry(frame, width=50, font=("Helvetica", 14))
        self.username_entry.pack()

        self.update_profile_btn = tk.Button(frame, text="Update Profile Name", width=25, font=("Helvetica", 14), command=self.update_profile)
        self.update_profile_btn.pack(pady=20)

        self.manage_wallets_btn = tk.Button(frame, text="Account Analyzer", width=20, font=("Helvetica", 14), command=lambda: self.controller.show_frame("WalletTransactionScreen"))
        self.manage_wallets_btn.pack(pady=5)

        self.change_password_btn = tk.Button(frame, text="Change Password", width=25, font=("Helvetica", 14), command=self.change_password)
        self.change_password_btn.pack(pady=5)  # New Button

        self.logout_btn = tk.Button(frame, text="Logout", width=25, font=("Helvetica", 14), command=self.logout_user)
        self.logout_btn.pack(pady=20)

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
        self.header_label.config(text=f"Welcome, {user.username}")
        self.username_entry.insert(0, user.username)

    def update_profile(self):
        new_username = self.username_entry.get().strip()
        email = self.controller.get_current_user().email
        if not new_username:
            messagebox.showerror("Error", "Username cannot be empty.")
            return
        success, message = self.controller.user_manager.update_profile(email, new_username)
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)

    def change_password(self):
        # Create a new window for changing password
        change_pw_window = tk.Toplevel(self)
        change_pw_window.title("Change Password")
        change_pw_window.geometry("400x300")

        tk.Label(change_pw_window, text="Change Password", font=("Helvetica", 16)).pack(pady=20)

        tk.Label(change_pw_window, text="Current Password", font=("Helvetica", 12)).pack(pady=(10, 5))
        current_pw_entry = tk.Entry(change_pw_window, show="*", width=30, font=("Helvetica", 12))
        current_pw_entry.pack()

        tk.Label(change_pw_window, text="New Password", font=("Helvetica", 12)).pack(pady=(10, 5))
        new_pw_entry = tk.Entry(change_pw_window, show="*", width=30, font=("Helvetica", 12))
        new_pw_entry.pack()

        tk.Label(change_pw_window, text="Confirm New Password", font=("Helvetica", 12)).pack(pady=(10, 5))
        confirm_pw_entry = tk.Entry(change_pw_window, show="*", width=30, font=("Helvetica", 12))
        confirm_pw_entry.pack()

        def submit_change_password():
            current_pw = current_pw_entry.get().strip()
            new_pw = new_pw_entry.get().strip()
            confirm_pw = confirm_pw_entry.get().strip()

            if not current_pw or not new_pw or not confirm_pw:
                messagebox.showerror("Error", "All fields are required.")
                return

            if new_pw != confirm_pw:
                messagebox.showerror("Error", "New passwords do not match.")
                return

            email = self.controller.get_current_user().email
            success, message = self.controller.user_manager.change_password(email, current_pw, new_pw)
            if success:
                messagebox.showinfo("Success", message)
                change_pw_window.destroy()
            else:
                messagebox.showerror("Error", message)

        submit_btn = tk.Button(change_pw_window, text="Submit", width=15, font=("Helvetica", 12), command=submit_change_password)
        submit_btn.pack(pady=20)

    def logout_user(self):
        self.controller.set_current_user(None)
        messagebox.showinfo("Success", "Logged out successfully.")
        self.controller.show_frame("LoginScreen")

    def clear_screen(self):
        for widget in self.winfo_children():
            widget.pack_forget()
        # Recreate widgets
        self.create_widgets()

# ---------------------------- Wallet Management Screen ---------------------------- #

class WalletTransactionScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.wallet_df = pd.DataFrame()  # Initialize empty DataFrame
        self.create_widgets()

    def create_widgets(self):
        # Use a standard Frame instead of a scrollable Canvas
        main_frame = tk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # ---------------------------- Wallet Management Section ---------------------------- #
        wallet_frame = tk.LabelFrame(main_frame, text="Manage Your Wallets", padx=10, pady=10)
        wallet_frame.pack(fill="x", padx=5, pady=5)

        self.wallet_listbox = tk.Listbox(wallet_frame, width=50, height=5, font=("Helvetica", 12))
        self.wallet_listbox.grid(row=0, column=0, columnspan=4, pady=5)

        self.add_wallet_btn = tk.Button(wallet_frame, text="Add Wallet", width=15, font=("Helvetica", 12), command=self.add_wallet)
        self.add_wallet_btn.grid(row=1, column=0, padx=5, pady=5)

        self.remove_wallet_btn = tk.Button(wallet_frame, text="Remove Wallet", width=15, font=("Helvetica", 12), command=self.remove_wallet)
        self.remove_wallet_btn.grid(row=1, column=1, padx=5, pady=5)

        self.view_summary_btn = tk.Button(wallet_frame, text="View Summary", width=15, font=("Helvetica", 12), command=self.view_summary)
        self.view_summary_btn.grid(row=1, column=2, padx=5, pady=5)

        self.back_to_profile_btn = tk.Button(wallet_frame, text="Back to Profile", width=15, font=("Helvetica", 12), command=lambda: self.controller.show_frame("ProfileScreen"))
        self.back_to_profile_btn.grid(row=1, column=3, padx=5, pady=5)

        # ---------------------------- Data Fetching Section ---------------------------- #
        fetch_frame = tk.LabelFrame(main_frame, text="Fetch Wallet Data", padx=10, pady=10)
        fetch_frame.pack(fill="x", padx=5, pady=15)

        tk.Label(fetch_frame, text="Select Wallet Address:", font=("Helvetica", 12)).grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.selected_wallet_var = tk.StringVar()
        self.wallet_dropdown = ttk.Combobox(fetch_frame, textvariable=self.selected_wallet_var, state="readonly", width=40, font=("Helvetica", 12))
        self.wallet_dropdown.grid(row=0, column=1, padx=5, pady=5)

        self.fetch_data_btn = tk.Button(fetch_frame, text="Fetch Data", width=15, font=("Helvetica", 12), command=self.fetch_wallet_data)
        self.fetch_data_btn.grid(row=0, column=2, padx=5, pady=5)

        self.status_label = tk.Label(fetch_frame, text="", font=("Helvetica", 12), fg="blue")
        self.status_label.grid(row=1, column=0, columnspan=3, pady=10)

        # ---------------------------- View Transactions Button ---------------------------- #
        self.view_transactions_btn = tk.Button(fetch_frame, text="View All Transactions", width=20, font=("Helvetica", 12), command=self.view_all_transactions)
        self.view_transactions_btn.grid(row=2, column=1, padx=5, pady=5)

        # ---------------------------- Filters and Options Section ---------------------------- #
        filter_frame = tk.LabelFrame(main_frame, text="Filters and Options", padx=10, pady=10)
        filter_frame.pack(fill="x", padx=5, pady=15)

        # Date Filter
        tk.Label(filter_frame, text="Date Range:", font=("Helvetica", 12)).grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.start_date_entry = tk.Entry(filter_frame, width=20, font=("Helvetica", 12))
        self.start_date_entry.grid(row=0, column=1, padx=5, pady=5)
        self.end_date_entry = tk.Entry(filter_frame, width=20, font=("Helvetica", 12))
        self.end_date_entry.grid(row=0, column=2, padx=5, pady=5)
        tk.Label(filter_frame, text="(YYYY-MM-DD)", font=("Helvetica", 10)).grid(row=0, column=3, padx=5, pady=5, sticky="w")

        # Amount Filter
        tk.Label(filter_frame, text="Amount Range (MATIC):", font=("Helvetica", 12)).grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.min_amount_entry = tk.Entry(filter_frame, width=20, font=("Helvetica", 12))
        self.min_amount_entry.grid(row=1, column=1, padx=5, pady=5)
        self.max_amount_entry = tk.Entry(filter_frame, width=20, font=("Helvetica", 12))
        self.max_amount_entry.grid(row=1, column=2, padx=5, pady=5)

        # Token Type Filter
        tk.Label(filter_frame, text="Token Type:", font=("Helvetica", 12)).grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.token_type_var = tk.StringVar()
        self.token_type_var.set("All")
        self.token_type_dropdown = ttk.Combobox(filter_frame, textvariable=self.token_type_var, state="readonly", values=["All", "MATIC", "ERC-20", "ERC-721"], width=20, font=("Helvetica", 12))
        self.token_type_dropdown.grid(row=2, column=1, padx=5, pady=5)

        # Sender/Receiver Filter
        tk.Label(filter_frame, text="Sender/Receiver Address:", font=("Helvetica", 12)).grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.address_entry = tk.Entry(filter_frame, width=40, font=("Helvetica", 12))
        self.address_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=5)

        # Status Filter
        tk.Label(filter_frame, text="Status:", font=("Helvetica", 12)).grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.status_var = tk.StringVar()
        self.status_var.set("All")
        self.status_dropdown = ttk.Combobox(filter_frame, textvariable=self.status_var, state="readonly", values=["All", "Success", "Fail"], width=20, font=("Helvetica", 12))
        self.status_dropdown.grid(row=4, column=1, padx=5, pady=5)

        # Search by Keyword
        tk.Label(filter_frame, text="Search Keyword:", font=("Helvetica", 12)).grid(row=5, column=0, padx=5, pady=5, sticky="e")
        self.keyword_entry = tk.Entry(filter_frame, width=40, font=("Helvetica", 12))
        self.keyword_entry.grid(row=5, column=1, columnspan=2, padx=5, pady=5)

        # Transaction Hash Search
        tk.Label(filter_frame, text="Transaction Hash:", font=("Helvetica", 12)).grid(row=6, column=0, padx=5, pady=5, sticky="e")
        self.tx_hash_entry = tk.Entry(filter_frame, width=40, font=("Helvetica", 12))
        self.tx_hash_entry.grid(row=6, column=1, columnspan=2, padx=5, pady=5)

        # Apply Filters Button
        self.apply_filters_btn = tk.Button(filter_frame, text="Apply Filters", width=15, font=("Helvetica", 12), command=self.apply_filters)
        self.apply_filters_btn.grid(row=7, column=1, padx=5, pady=10)

        # ---------------------------- Other Options Section ---------------------------- #
        options_frame = tk.LabelFrame(main_frame, text="Other Options", padx=10, pady=10)
        options_frame.pack(fill="x", padx=5, pady=15)

        # View ERC-20 Token Balances
        self.view_erc20_balances_btn = tk.Button(options_frame, text="View ERC-20 Balances", width=25, font=("Helvetica", 12), command=self.view_erc20_balances)
        self.view_erc20_balances_btn.grid(row=0, column=0, padx=5, pady=5)

        # View ERC-721 NFTs
        self.view_erc721_nfts_btn = tk.Button(options_frame, text="View ERC-721 NFTs", width=25, font=("Helvetica", 12), command=self.view_erc721_nfts)
        self.view_erc721_nfts_btn.grid(row=0, column=1, padx=5, pady=5)

        # View Portfolio Value in MATIC
        self.view_portfolio_matic_btn = tk.Button(options_frame, text="View Portfolio Value (MATIC)", width=25, font=("Helvetica", 12), command=self.view_portfolio_value_matic)
        self.view_portfolio_matic_btn.grid(row=1, column=0, padx=5, pady=5)

        # View Portfolio Value in USD
        self.view_portfolio_usd_btn = tk.Button(options_frame, text="View Portfolio Value (USD)", width=25, font=("Helvetica", 12), command=self.view_portfolio_value_usd)
        self.view_portfolio_usd_btn.grid(row=1, column=1, padx=5, pady=5)

    # ---------------------------- Wallet Management Methods ---------------------------- #

    def add_wallet(self):
        wallet_address = simpledialog.askstring("Add Wallet", "Enter Polygon wallet address:")
        if wallet_address:
            email = self.controller.get_current_user().email
            success, message = self.controller.user_manager.add_wallet(email, wallet_address)
            if success:
                self.update_wallet_list()
                self.update_wallet_dropdown()
                messagebox.showinfo("Success", message)
            else:
                messagebox.showerror("Error", message)

    def remove_wallet(self):
        selected_index = self.wallet_listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "Please select a wallet to remove.")
            return
        selected_wallet = self.wallet_listbox.get(selected_index)
        if selected_wallet == "No wallets added yet.":
            messagebox.showerror("Error", "No wallets to remove.")
            return
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to remove the wallet:\n{selected_wallet}?")
        if confirm:
            email = self.controller.get_current_user().email
            success, message = self.controller.user_manager.remove_wallet(email, selected_wallet)
            if success:
                self.update_wallet_list()
                self.update_wallet_dropdown()
                messagebox.showinfo("Success", message)
            else:
                messagebox.showerror("Error", message)

    def view_summary(self):
        user = self.controller.get_current_user()
        if not user.wallets:
            messagebox.showinfo("Wallet Summary", "No wallets to summarize.")
            return
        summary = ""
        for wallet in user.wallets:
            balance = PolygonWallet.get_wallet_balance(wallet)
            if balance is not None:
                summary += f"Wallet: {wallet}\nBalance: {balance:.4f} MATIC\n\n"
            else:
                summary += f"Wallet: {wallet}\nBalance: Unable to fetch data.\n\n"
        messagebox.showinfo("Wallet Summary", summary)

    def update_wallet_list(self):
        self.wallet_listbox.delete(0, tk.END)
        user = self.controller.get_current_user()
        if user:
            wallets = self.controller.user_manager.get_wallets(user.email)
            if wallets:
                for wallet in wallets:
                    self.wallet_listbox.insert(tk.END, wallet)
            else:
                self.wallet_listbox.insert(tk.END, "No wallets added yet.")

    # ---------------------------- Data Fetching Methods ---------------------------- #

    def update_wallet_dropdown(self):
        user = self.controller.get_current_user()
        if user:
            wallets = self.controller.user_manager.get_wallets(user.email)
            self.wallet_dropdown['values'] = wallets
            if wallets:
                self.wallet_dropdown.current(0)
                self.selected_wallet_var.set(wallets[0])
            else:
                self.wallet_dropdown.set("")
        else:
            self.wallet_dropdown.set("")

    def fetch_wallet_data(self):
        selected_wallet = self.selected_wallet_var.get()
        if not selected_wallet:
            messagebox.showerror("Error", "Please select a wallet address to fetch data.")
            return

        # Disable the fetch button to prevent multiple clicks
        self.fetch_data_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Fetching data...")

        # Start the fetching in a separate thread
        threading.Thread(target=self.fetch_data_thread, args=(selected_wallet,), daemon=True).start()

    def fetch_data_thread(self, wallet_address):
        transactions = PolygonWallet.get_wallet_transactions(wallet_address)
        if transactions is None:
            self.after(0, lambda: messagebox.showerror("Error", "Failed to fetch transactions."))
            self.after(0, lambda: self.status_label.config(text="Failed to fetch data."))
        else:
            # Convert transactions to DataFrame
            if transactions:
                self.wallet_df = pd.DataFrame(transactions)
                num_transactions = len(self.wallet_df)
                status_message = f"Fetched {num_transactions} transactions."
            else:
                self.wallet_df = pd.DataFrame()
                status_message = "No transactions found."

            # Update the status label
            self.after(0, lambda: self.status_label.config(text=status_message))

        # Re-enable the fetch button
        self.after(0, lambda: self.fetch_data_btn.config(state=tk.NORMAL))

    # ---------------------------- View All Transactions Method ---------------------------- #

    def view_all_transactions(self):
        if self.wallet_df.empty:
            messagebox.showerror("Error", "No data to display. Please fetch data first.")
            return

        # Create a new Toplevel window
        window = tk.Toplevel(self)
        window.title("All Transactions")
        window.geometry("1000x600")  # Adjust size as needed

        # Instruction Label
        tk.Label(window, text="Double click to view complete details of the transaction", font=("Helvetica", 12), fg="blue").pack(pady=5)

        # Create a frame to hold the Treeview and scrollbar
        frame = tk.Frame(window)
        frame.pack(fill=tk.BOTH, expand=True)

        # Create a Treeview widget
        tree = ttk.Treeview(frame)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Define the columns to display
        columns = ("hash", "from", "to", "value_matic", "timeStamp", "blockNumber", "gasUsed", "isError")

        tree["columns"] = columns

        # Format the columns
        tree.column("#0", width=0, stretch=tk.NO)  # Hide the first empty column
        tree.heading("#0", text="", anchor=tk.W)

        # Set up the columns
        for col in columns:
            tree.column(col, anchor=tk.W, width=120)
            tree.heading(col, text=col, anchor=tk.W)

        # Process the data
        df = self.wallet_df.copy()

        # Convert value from Wei to MATIC
        df["value_matic"] = df["value"].astype(float) / (10 ** 18)

        # Convert timestamp to datetime
        df["timeStamp"] = df["timeStamp"].apply(lambda x: datetime.datetime.fromtimestamp(int(x)).strftime('%Y-%m-%d %H:%M:%S'))

        # Insert data into the Treeview
        for index, row in df.iterrows():
            tree.insert("", tk.END, values=(row["hash"], row["from"], row["to"], f"{row['value_matic']:.4f}", row["timeStamp"], row["blockNumber"], row["gasUsed"], row["isError"]))

        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)

        # Bind double-click event
        tree.bind("<Double-1>", lambda event: self.view_transaction_details(tree))

    def view_transaction_details(self, tree, df=None):
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a transaction to view details.")
            return
        tx_values = tree.item(selected_item, 'values')
        tx_hash = tx_values[0]
        if df is None:
            transaction = self.wallet_df[self.wallet_df['hash'] == tx_hash].iloc[0]
        else:
            transaction = df[df['hash'] == tx_hash].iloc[0]
        details = f"Transaction Hash: {transaction['hash']}\n"
        details += f"From: {transaction['from']}\n"
        details += f"To: {transaction['to']}\n"
        details += f"Value (MATIC): {float(transaction['value']) / (10 ** 18):.4f}\n"
        details += f"Gas Used: {transaction['gasUsed']}\n"
        details += f"Gas Price: {transaction['gasPrice']}\n"
        details += f"Gas Fee (MATIC): {(float(transaction['gasUsed']) * float(transaction['gasPrice'])) / (10 ** 18):.4f}\n"
        details += f"Block Number: {transaction['blockNumber']}\n"
        details += f"TimeStamp: {datetime.datetime.fromtimestamp(int(transaction['timeStamp'])).strftime('%Y-%m-%d %H:%M:%S')}\n"
        details += f"Contract Address: {transaction['contractAddress']}\n"
        details += f"Is Error: {transaction['isError']}\n"

        # Include ERC-20 Token Transfers
        erc20_transfers = PolygonWallet.get_erc20_token_transfer(tx_hash)
        if erc20_transfers:
            details += "\nERC-20 Token Transfers:\n"
            for transfer in erc20_transfers:
                token_symbol = transfer['tokenSymbol']
                token_value = int(transfer['value']) / (10 ** int(transfer['tokenDecimal']))
                details += f"  Token: {token_symbol} Amount: {token_value}\n"

        # Include ERC-721 Token Transfers
        erc721_transfers = PolygonWallet.get_erc721_token_transfer(tx_hash)
        if erc721_transfers:
            details += "\nERC-721 Token Transfers:\n"
            for transfer in erc721_transfers:
                token_name = transfer['tokenName']
                token_id = transfer['tokenID']
                details += f"  Token: {token_name} TokenID: {token_id}\n"

        # Display detailed transaction information
        detail_window = tk.Toplevel(self)
        detail_window.title("Transaction Details")
        detail_window.geometry("600x400")

        text = tk.Text(detail_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, details)
        text.config(state=tk.DISABLED)

    # ---------------------------- Filters and Options Methods ---------------------------- #

    def apply_filters(self):
        if self.wallet_df.empty:
            messagebox.showerror("Error", "No data to filter. Please fetch data first.")
            return

        df = self.wallet_df.copy()

        # Convert value from Wei to MATIC
        df["value_matic"] = df["value"].astype(float) / (10 ** 18)
        # Convert timestamp to datetime
        df["timeStamp"] = df["timeStamp"].apply(lambda x: datetime.datetime.fromtimestamp(int(x)))

        # Date Filter
        start_date_str = self.start_date_entry.get().strip()
        end_date_str = self.end_date_entry.get().strip()
        if start_date_str:
            try:
                start_date = datetime.datetime.strptime(start_date_str, "%Y-%m-%d")
                df = df[df["timeStamp"] >= start_date]
            except ValueError:
                messagebox.showerror("Error", "Invalid start date format. Use YYYY-MM-DD.")
                return
        if end_date_str:
            try:
                end_date = datetime.datetime.strptime(end_date_str, "%Y-%m-%d")
                end_date += datetime.timedelta(days=1)  # Include the end date
                df = df[df["timeStamp"] < end_date]
            except ValueError:
                messagebox.showerror("Error", "Invalid end date format. Use YYYY-MM-DD.")
                return

        # Amount Filter
        min_amount_str = self.min_amount_entry.get().strip()
        max_amount_str = self.max_amount_entry.get().strip()
        if min_amount_str:
            try:
                min_amount = float(min_amount_str)
                df = df[df["value_matic"] >= min_amount]
            except ValueError:
                messagebox.showerror("Error", "Invalid minimum amount.")
                return
        if max_amount_str:
            try:
                max_amount = float(max_amount_str)
                df = df[df["value_matic"] <= max_amount]
            except ValueError:
                messagebox.showerror("Error", "Invalid maximum amount.")
                return

        # Token Type Filter
        token_type = self.token_type_var.get()
        if token_type != "All":
            if token_type == "MATIC":
                df = df[df["input"] == "0x"]
            elif token_type == "ERC-20":
                erc20_tx_hashes = self.get_erc20_tx_hashes(self.selected_wallet_var.get())
                df = df[df["hash"].isin(erc20_tx_hashes)]
            elif token_type == "ERC-721":
                erc721_tx_hashes = self.get_erc721_tx_hashes(self.selected_wallet_var.get())
                df = df[df["hash"].isin(erc721_tx_hashes)]

        # Sender/Receiver Filter
        address_filter = self.address_entry.get().strip()
        if address_filter:
            address_filter = address_filter.lower()
            df = df[(df["from"].str.lower() == address_filter) | (df["to"].str.lower() == address_filter)]

        # Status Filter
        status = self.status_var.get()
        if status != "All":
            if status == "Success":
                df = df[df["isError"] == "0"]
            elif status == "Fail":
                df = df[df["isError"] != "0"]

        # Keyword Search
        keyword = self.keyword_entry.get().strip()
        if keyword:
            df = df[df.apply(lambda row: keyword.lower() in str(row).lower(), axis=1)]

        # Transaction Hash Search
        tx_hash = self.tx_hash_entry.get().strip()
        if tx_hash:
            df = df[df["hash"].str.contains(tx_hash, case=False)]

        # Show the filtered transactions
        if df.empty:
            messagebox.showinfo("No Results", "No transactions match the filters.")
        else:
            self.show_transactions(df)

    def get_erc20_tx_hashes(self, address):
        erc20_transfers = PolygonWallet.get_erc20_token_transfers(address)
        tx_hashes = set(transfer['hash'] for transfer in erc20_transfers)
        return tx_hashes

    def get_erc721_tx_hashes(self, address):
        erc721_transfers = PolygonWallet.get_erc721_token_transfers(address)
        tx_hashes = set(transfer['hash'] for transfer in erc721_transfers)
        return tx_hashes

    def show_transactions(self, df):
        # Create a new Toplevel window
        window = tk.Toplevel(self)
        window.title("Filtered Transactions")
        window.geometry("1000x600")  # Adjust size as needed

        # Instruction Label
        tk.Label(window, text="Double click to view complete details of the transaction", font=("Helvetica", 12), fg="blue").pack(pady=5)

        # Create a frame to hold the Treeview and scrollbar
        frame = tk.Frame(window)
        frame.pack(fill=tk.BOTH, expand=True)

        # Create a Treeview widget
        tree = ttk.Treeview(frame)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Define the columns to display
        columns = ("hash", "from", "to", "value_matic", "timeStamp", "blockNumber", "gasUsed", "isError")

        tree["columns"] = columns

        # Format the columns
        tree.column("#0", width=0, stretch=tk.NO)  # Hide the first empty column
        tree.heading("#0", text="", anchor=tk.W)

        # Set up the columns
        for col in columns:
            tree.column(col, anchor=tk.W, width=120)
            tree.heading(col, text=col, anchor=tk.W)

        # Insert data into the Treeview
        for index, row in df.iterrows():
            tree.insert("", tk.END, values=(row["hash"], row["from"], row["to"], f"{row['value_matic']:.4f}", row["timeStamp"].strftime('%Y-%m-%d %H:%M:%S'), row["blockNumber"], row["gasUsed"], row["isError"]))

        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)

        # Bind double-click event
        tree.bind("<Double-1>", lambda event: self.view_transaction_details(tree, df))

    # ---------------------------- Other Options Methods ---------------------------- #

    def view_erc20_balances(self):
        address = self.selected_wallet_var.get()
        if not address:
            messagebox.showerror("Error", "Please select a wallet address.")
            return

        # Disable the button
        self.view_erc20_balances_btn.config(state=tk.DISABLED)
        threading.Thread(target=self.fetch_erc20_balances_thread, args=(address,), daemon=True).start()

    def fetch_erc20_balances_thread(self, address):
        balances = PolygonWallet.get_erc20_token_balances(address)
        if balances is None:
            self.after(0, lambda: messagebox.showerror("Error", "Failed to fetch ERC-20 token balances."))
        else:
            self.after(0, lambda: self.show_erc20_balances(balances))
        self.after(0, lambda: self.view_erc20_balances_btn.config(state=tk.NORMAL))

    def show_erc20_balances(self, balances):
        if not balances:
            messagebox.showinfo("ERC-20 Token Balances", "No ERC-20 tokens found in the wallet.")
            return

        # Create a new window to display balances
        window = tk.Toplevel(self)
        window.title("ERC-20 Token Balances")
        window.geometry("600x400")

        tree = ttk.Treeview(window)
        tree.pack(fill=tk.BOTH, expand=True)

        columns = ("Token", "Balance")

        tree["columns"] = columns

        tree.column("#0", width=0, stretch=tk.NO)
        tree.heading("#0", text="", anchor=tk.W)

        for col in columns:
            tree.column(col, anchor=tk.W, width=200)
            tree.heading(col, text=col, anchor=tk.W)

        for token, balance in balances.items():
            tree.insert("", tk.END, values=(token, balance))

        # Add scrollbar
        scrollbar = ttk.Scrollbar(window, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)

    def view_erc721_nfts(self):
        address = self.selected_wallet_var.get()
        if not address:
            messagebox.showerror("Error", "Please select a wallet address.")
            return

        # Disable the button
        self.view_erc721_nfts_btn.config(state=tk.DISABLED)
        threading.Thread(target=self.fetch_erc721_nfts_thread, args=(address,), daemon=True).start()

    def fetch_erc721_nfts_thread(self, address):
        tokens = PolygonWallet.get_erc721_tokens(address)
        if tokens is None:
            self.after(0, lambda: messagebox.showerror("Error", "Failed to fetch ERC-721 NFTs."))
        else:
            self.after(0, lambda: self.show_erc721_nfts(tokens))
        self.after(0, lambda: self.view_erc721_nfts_btn.config(state=tk.NORMAL))

    def show_erc721_nfts(self, tokens):
        if not tokens:
            messagebox.showinfo("ERC-721 NFTs", "No ERC-721 NFTs found in the wallet.")
            return

        # Create a new window to display NFTs
        window = tk.Toplevel(self)
        window.title("ERC-721 NFTs")
        window.geometry("600x400")

        tree = ttk.Treeview(window)
        tree.pack(fill=tk.BOTH, expand=True)

        columns = ("Token Name", "Token IDs")

        tree["columns"] = columns

        tree.column("#0", width=0, stretch=tk.NO)
        tree.heading("#0", text="", anchor=tk.W)

        for col in columns:
            tree.column(col, anchor=tk.W, width=200)
            tree.heading(col, text=col, anchor=tk.W)

        for token_name, token_ids in tokens.items():
            tree.insert("", tk.END, values=(token_name, ', '.join(token_ids)))

        # Add scrollbar
        scrollbar = ttk.Scrollbar(window, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)

    def view_portfolio_value_matic(self):
        address = self.selected_wallet_var.get()
        if not address:
            messagebox.showerror("Error", "Please select a wallet address.")
            return

        # Disable the button
        self.view_portfolio_matic_btn.config(state=tk.DISABLED)
        threading.Thread(target=self.fetch_portfolio_value_matic_thread, args=(address,), daemon=True).start()

    def fetch_portfolio_value_matic_thread(self, address):
        matic_balance = PolygonWallet.get_wallet_balance(address)
        erc20_balances = PolygonWallet.get_erc20_token_balances(address)
        token_prices = PolygonWallet.get_token_prices_in_matic(erc20_balances.keys())
        total_value = matic_balance
        for token, balance in erc20_balances.items():
            token_price = token_prices.get(token, 0)
            total_value += balance * token_price
        self.after(0, lambda: messagebox.showinfo("Portfolio Value (MATIC)", f"Total Portfolio Value: {total_value:.4f} MATIC"))
        self.after(0, lambda: self.view_portfolio_matic_btn.config(state=tk.NORMAL))

    def view_portfolio_value_usd(self):
        address = self.selected_wallet_var.get()
        if not address:
            messagebox.showerror("Error", "Please select a wallet address.")
            return

        # Disable the button
        self.view_portfolio_usd_btn.config(state=tk.DISABLED)
        threading.Thread(target=self.fetch_portfolio_value_usd_thread, args=(address,), daemon=True).start()

    def fetch_portfolio_value_usd_thread(self, address):
        matic_balance = PolygonWallet.get_wallet_balance(address)
        erc20_balances = PolygonWallet.get_erc20_token_balances(address)
        matic_price_usd = PolygonWallet.get_matic_price_in_usd()
        token_prices = PolygonWallet.get_token_prices_in_matic(erc20_balances.keys())
        total_value_matic = matic_balance
        for token, balance in erc20_balances.items():
            token_price = token_prices.get(token, 0)
            total_value_matic += balance * token_price
        if matic_price_usd is not None:
            total_value_usd = total_value_matic * matic_price_usd
            self.after(0, lambda: messagebox.showinfo("Portfolio Value (USD)", f"Total Portfolio Value: ${total_value_usd:.2f} USD"))
        else:
            self.after(0, lambda: messagebox.showerror("Error", "Failed to fetch MATIC price in USD."))
        self.after(0, lambda: self.view_portfolio_usd_btn.config(state=tk.NORMAL))

    # ---------------------------- Override tkraise ---------------------------- #

    def tkraise(self, *args, **kwargs):
        self.update_wallet_list()
        self.update_wallet_dropdown()
        super().tkraise(*args, **kwargs)

    # ---------------------------- View Transaction Details ---------------------------- #

    def view_transaction_details(self, tree, df=None):
        selected_item = tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a transaction to view details.")
            return
        tx_values = tree.item(selected_item, 'values')
        tx_hash = tx_values[0]
        if df is None:
            transaction = self.wallet_df[self.wallet_df['hash'] == tx_hash].iloc[0]
        else:
            transaction = df[df['hash'] == tx_hash].iloc[0]
        details = f"Transaction Hash: {transaction['hash']}\n"
        details += f"From: {transaction['from']}\n"
        details += f"To: {transaction['to']}\n"
        details += f"Value (MATIC): {float(transaction['value']) / (10 ** 18):.4f}\n"
        details += f"Gas Used: {transaction['gasUsed']}\n"
        details += f"Gas Price: {transaction['gasPrice']}\n"
        details += f"Gas Fee (MATIC): {(float(transaction['gasUsed']) * float(transaction['gasPrice'])) / (10 ** 18):.4f}\n"
        details += f"Block Number: {transaction['blockNumber']}\n"
        details += f"TimeStamp: {datetime.datetime.fromtimestamp(int(transaction['timeStamp'])).strftime('%Y-%m-%d %H:%M:%S')}\n"
        details += f"Contract Address: {transaction['contractAddress']}\n"
        details += f"Is Error: {transaction['isError']}\n"

        # Include ERC-20 Token Transfers
        erc20_transfers = PolygonWallet.get_erc20_token_transfer(tx_hash)
        if erc20_transfers:
            details += "\nERC-20 Token Transfers:\n"
            for transfer in erc20_transfers:
                token_symbol = transfer['tokenSymbol']
                token_value = int(transfer['value']) / (10 ** int(transfer['tokenDecimal']))
                details += f"  Token: {token_symbol} Amount: {token_value}\n"

        # Include ERC-721 Token Transfers
        erc721_transfers = PolygonWallet.get_erc721_token_transfer(tx_hash)
        if erc721_transfers:
            details += "\nERC-721 Token Transfers:\n"
            for transfer in erc721_transfers:
                token_name = transfer['tokenName']
                token_id = transfer['tokenID']
                details += f"  Token: {token_name} TokenID: {token_id}\n"

        # Display detailed transaction information
        detail_window = tk.Toplevel(self)
        detail_window.title("Transaction Details")
        detail_window.geometry("600x400")

        text = tk.Text(detail_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, details)
        text.config(state=tk.DISABLED)

# ---------------------------- Main Execution ---------------------------- #

if __name__ == "__main__":
    app = AccountAnalyzerApp()
    app.mainloop()
