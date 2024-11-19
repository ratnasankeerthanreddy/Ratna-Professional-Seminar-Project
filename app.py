import tkinter as tk
from tkinter import messagebox
import json
import os
import requests
import datetime

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
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON: {e}")
                    users_data = {}
            if isinstance(users_data, list):
                # Old format
                for user_dict in users_data:
                    email = user_dict.get('email')
                    if email:
                        self.users[email] = User(
                            username=user_dict.get("username", ""),
                            email=email,
                            password=user_dict.get("password", ""),
                            profile=user_dict.get("profile", {}),
                            wallets=user_dict.get("wallets", [])
                        )
            elif isinstance(users_data, dict):
                # New format
                for email, data in users_data.items():
                    self.users[email] = User(
                        username=data.get("username", ""),
                        email=email,
                        password=data.get("password", ""),
                        profile=data.get("profile", {}),
                        wallets=data.get("wallets", [])
                    )
            else:
                # Invalid format
                print("Invalid format in users.json")
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
        self.geometry("800x600")
        self.current_user = None
        self.user_manager = UserManager()
        self.current_wallet = None  # Added to store the current wallet
        self.container = tk.Frame(self)
        self.container.pack(side="top", fill="both", expand=True)
        self.frames = {}
        for F in (LoginScreen, RegisterScreen, ResetPasswordScreen, ProfileScreen, WalletManagementScreen, TransactionAnalysisScreen):
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
        if user is None or user.username == "":
            messagebox.showerror("Error", "No user logged in or username missing.")
            self.controller.show_frame("LoginScreen")
            return
        tk.Label(self, text=f"Welcome, {user.username}").pack()
        tk.Label(self, text="Profile Information").pack()
        tk.Label(self, text="Username").pack()
        self.username_entry = tk.Entry(self)
        self.username_entry.insert(0, user.username)
        self.username_entry.pack()
        tk.Button(self, text="Update Profile", command=self.update_profile).pack()
        tk.Button(self, text="Manage Wallets", command=lambda: self.controller.show_frame("WalletManagementScreen")).pack()
        tk.Button(self, text="Transaction Analysis", command=lambda: self.controller.show_frame("TransactionAnalysisScreen")).pack()
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

class WalletManagementScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.selected_wallet = None

        # Widgets
        tk.Label(self, text="Wallet Management").pack()

        # Entry to add new wallet
        tk.Label(self, text="Add Wallet Address").pack()
        self.wallet_entry = tk.Entry(self)
        self.wallet_entry.pack()
        tk.Button(self, text="Add Wallet", command=self.add_wallet).pack()

        # Listbox to display wallets
        tk.Label(self, text="Your Wallets").pack()
        self.wallet_listbox = tk.Listbox(self)
        self.wallet_listbox.pack(fill=tk.BOTH, expand=True)
        self.wallet_listbox.bind('<<ListboxSelect>>', self.on_wallet_select)

        # Buttons to remove or switch wallets
        tk.Button(self, text="Remove Selected Wallet", command=self.remove_wallet).pack()
        tk.Button(self, text="Switch to Selected Wallet", command=self.switch_wallet).pack()

        # Button to go back to Profile
        tk.Button(self, text="Back to Profile", command=lambda: controller.show_frame("ProfileScreen")).pack()

    def tkraise(self, *args, **kwargs):
        self.update_wallet_list()
        super().tkraise(*args, **kwargs)

    def add_wallet(self):
        wallet_address = self.wallet_entry.get()
        if wallet_address:
            user = self.controller.get_current_user()
            if wallet_address not in user.wallets:
                user.wallets.append(wallet_address)
                self.controller.user_manager.save_users()
                messagebox.showinfo("Success", "Wallet added.")
                self.update_wallet_list()
            else:
                messagebox.showerror("Error", "Wallet already added.")
        else:
            messagebox.showerror("Error", "Please enter a wallet address.")

    def update_wallet_list(self):
        self.wallet_listbox.delete(0, tk.END)
        user = self.controller.get_current_user()
        if user:
            for wallet in user.wallets:
                self.wallet_listbox.insert(tk.END, wallet)

    def remove_wallet(self):
        selected_indices = self.wallet_listbox.curselection()
        if selected_indices:
            index = selected_indices[0]
            user = self.controller.get_current_user()
            wallet = user.wallets.pop(index)
            self.controller.user_manager.save_users()
            messagebox.showinfo("Success", f"Wallet {wallet} removed.")
            self.update_wallet_list()
        else:
            messagebox.showerror("Error", "No wallet selected.")

    def switch_wallet(self):
        selected_indices = self.wallet_listbox.curselection()
        if selected_indices:
            index = selected_indices[0]
            user = self.controller.get_current_user()
            wallet = user.wallets[index]
            self.controller.current_wallet = wallet
            messagebox.showinfo("Success", f"Switched to wallet {wallet}.")
        else:
            messagebox.showerror("Error", "No wallet selected.")

    def on_wallet_select(self, event):
        widget = event.widget
        selection = widget.curselection()
        if selection:
            index = selection[0]
            self.selected_wallet = widget.get(index)
        else:
            self.selected_wallet = None

class TransactionAnalysisScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.api_key = "vqxpVo5aVV5DTWl5STTJom02Gz4onWRO"
        self.transactions = []
        self.token_transactions = []
        self.nft_transactions = []

        # Widgets
        tk.Label(self, text="Transaction Analysis").pack()

        # Display current wallet
        self.wallet_label = tk.Label(self, text="Current Wallet: None")
        self.wallet_label.pack()

        # Button to load transactions
        tk.Button(self, text="Load Transactions", command=self.load_transactions).pack()

        # Filters and search options can be added here
        tk.Label(self, text="Filter Transactions").pack()

        tk.Label(self, text="From Date (YYYY-MM-DD)").pack()
        self.from_date_entry = tk.Entry(self)
        self.from_date_entry.pack()

        tk.Label(self, text="To Date (YYYY-MM-DD)").pack()
        self.to_date_entry = tk.Entry(self)
        self.to_date_entry.pack()

        tk.Label(self, text="Min Amount (MATIC)").pack()
        self.min_amount_entry = tk.Entry(self)
        self.min_amount_entry.pack()

        tk.Label(self, text="Max Amount (MATIC)").pack()
        self.max_amount_entry = tk.Entry(self)
        self.max_amount_entry.pack()

        tk.Label(self, text="Transaction Type").pack()
        self.tx_type_var = tk.StringVar()
        self.tx_type_var.set("All")  # default value

        tk.Radiobutton(self, text="All", variable=self.tx_type_var, value="All").pack(anchor=tk.W)
        tk.Radiobutton(self, text="Normal", variable=self.tx_type_var, value="Normal").pack(anchor=tk.W)
        tk.Radiobutton(self, text="ERC-20", variable=self.tx_type_var, value="ERC-20").pack(anchor=tk.W)
        tk.Radiobutton(self, text="ERC-721", variable=self.tx_type_var, value="ERC-721").pack(anchor=tk.W)

        tk.Button(self, text="Apply Filters", command=self.apply_filters).pack()

        tk.Label(self, text="Search Transactions").pack()
        tk.Label(self, text="Transaction Hash or Address").pack()
        self.search_entry = tk.Entry(self)
        self.search_entry.pack()
        tk.Button(self, text="Search", command=self.search_transactions).pack()

        # Transaction list
        self.transaction_listbox = tk.Listbox(self)
        self.transaction_listbox.pack(fill=tk.BOTH, expand=True)

        # Back to Profile
        tk.Button(self, text="Back to Profile", command=lambda: controller.show_frame("ProfileScreen")).pack()

    def tkraise(self, *args, **kwargs):
        if self.controller.current_wallet:
            self.wallet_label.config(text=f"Current Wallet: {self.controller.current_wallet}")
        else:
            self.wallet_label.config(text="Current Wallet: None")
        super().tkraise(*args, **kwargs)

    def load_transactions(self):
        wallet_address = self.controller.current_wallet
        if wallet_address:
            self.fetch_transactions(wallet_address)
            self.display_transactions()
        else:
            messagebox.showerror("Error", "No wallet selected.")

    def fetch_transactions(self, wallet_address):
        # Fetch transactions using PolygonScan API

        base_url = "https://api.polygonscan.com/api"

        # Fetch normal transactions
        params = {
            "module": "account",
            "action": "txlist",
            "address": wallet_address,
            "startblock": 0,
            "endblock": 99999999,
            "page": 1,
            "offset": 100,
            "sort": "desc",
            "apikey": self.api_key
        }
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            result = response.json()
            if result["status"] == "1":
                self.transactions = result["result"]
            else:
                messagebox.showerror("Error", f"Error fetching transactions: {result['message']}")
                return
        else:
            messagebox.showerror("Error", f"HTTP Error: {response.status_code}")
            return

        # Fetch ERC-20 token transactions
        params['action'] = 'tokentx'
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            result = response.json()
            if result["status"] == "1":
                self.token_transactions = result["result"]
            else:
                self.token_transactions = []
        else:
            messagebox.showerror("Error", f"HTTP Error: {response.status_code}")
            return

        # Fetch ERC-721 token transactions
        params['action'] = 'tokennfttx'
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            result = response.json()
            if result["status"] == "1":
                self.nft_transactions = result["result"]
            else:
                self.nft_transactions = []
        else:
            messagebox.showerror("Error", f"HTTP Error: {response.status_code}")
            return

    def display_transactions(self):
        self.transaction_listbox.delete(0, tk.END)
        # Combine all transactions
        all_transactions = self.transactions + self.token_transactions + self.nft_transactions
        # Sort by timeStamp
        all_transactions.sort(key=lambda x: int(x['timeStamp']), reverse=True)
        for tx in all_transactions:
            tx_hash = tx['hash']
            time_stamp = datetime.datetime.fromtimestamp(int(tx['timeStamp']))
            if 'tokenSymbol' in tx:
                # Token transaction
                token_symbol = tx['tokenSymbol']
                token_value = int(tx['value']) / (10 ** int(tx['tokenDecimal']))
                tx_summary = f"Token Tx: {token_symbol}, Amount: {token_value}, Hash: {tx_hash[:10]}..., Time: {time_stamp}"
            elif 'tokenID' in tx:
                # NFT transaction
                token_name = tx.get('tokenName', 'Unknown')
                token_id = tx['tokenID']
                tx_summary = f"NFT Tx: {token_name}, Token ID: {token_id}, Hash: {tx_hash[:10]}..., Time: {time_stamp}"
            else:
                # Normal transaction
                value = int(tx['value']) / 1e18  # Convert wei to MATIC
                tx_summary = f"Tx: Value: {value} MATIC, Hash: {tx_hash[:10]}..., Time: {time_stamp}"
            self.transaction_listbox.insert(tk.END, tx_summary)

    def apply_filters(self):
        filtered_transactions = []

        tx_type = self.tx_type_var.get()

        if tx_type == "All":
            filtered_transactions = self.transactions + self.token_transactions + self.nft_transactions
        elif tx_type == "Normal":
            filtered_transactions = self.transactions
        elif tx_type == "ERC-20":
            filtered_transactions = self.token_transactions
        elif tx_type == "ERC-721":
            filtered_transactions = self.nft_transactions

        # Convert timestamp strings to integers
        for tx in filtered_transactions:
            tx['timeStamp'] = int(tx['timeStamp'])

        # Apply date filters
        from_date = self.from_date_entry.get()
        to_date = self.to_date_entry.get()

        if from_date:
            try:
                from_timestamp = int(datetime.datetime.strptime(from_date, "%Y-%m-%d").timestamp())
                filtered_transactions = [tx for tx in filtered_transactions if tx['timeStamp'] >= from_timestamp]
            except ValueError:
                messagebox.showerror("Error", "Invalid From Date format. Use YYYY-MM-DD.")
                return

        if to_date:
            try:
                to_timestamp = int(datetime.datetime.strptime(to_date, "%Y-%m-%d").timestamp())
                filtered_transactions = [tx for tx in filtered_transactions if tx['timeStamp'] <= to_timestamp]
            except ValueError:
                messagebox.showerror("Error", "Invalid To Date format. Use YYYY-MM-DD.")
                return

        # Apply amount filters
        min_amount = self.min_amount_entry.get()
        max_amount = self.max_amount_entry.get()

        if min_amount:
            try:
                min_amount = float(min_amount)
                if tx_type in ["All", "Normal"]:
                    filtered_transactions = [tx for tx in filtered_transactions if ('value' in tx and (int(tx['value']) / 1e18) >= min_amount)]
                elif tx_type == "ERC-20":
                    filtered_transactions = [tx for tx in filtered_transactions if ('value' in tx and (int(tx['value']) / (10 ** int(tx['tokenDecimal']))) >= min_amount)]
                # For ERC-721, amount is not applicable
            except ValueError:
                messagebox.showerror("Error", "Invalid Min Amount.")
                return

        if max_amount:
            try:
                max_amount = float(max_amount)
                if tx_type in ["All", "Normal"]:
                    filtered_transactions = [tx for tx in filtered_transactions if ('value' in tx and (int(tx['value']) / 1e18) <= max_amount)]
                elif tx_type == "ERC-20":
                    filtered_transactions = [tx for tx in filtered_transactions if ('value' in tx and (int(tx['value']) / (10 ** int(tx['tokenDecimal']))) <= max_amount)]
                # For ERC-721, amount is not applicable
            except ValueError:
                messagebox.showerror("Error", "Invalid Max Amount.")
                return

        # Sort transactions by timestamp descending
        filtered_transactions.sort(key=lambda x: x['timeStamp'], reverse=True)

        self.display_filtered_transactions(filtered_transactions)

    def display_filtered_transactions(self, transactions):
        self.transaction_listbox.delete(0, tk.END)
        for tx in transactions:
            tx_hash = tx['hash']
            time_stamp = datetime.datetime.fromtimestamp(int(tx['timeStamp']))
            if 'tokenSymbol' in tx:
                # Token transaction
                token_symbol = tx['tokenSymbol']
                token_value = int(tx['value']) / (10 ** int(tx['tokenDecimal']))
                tx_summary = f"Token Tx: {token_symbol}, Amount: {token_value}, Hash: {tx_hash[:10]}..., Time: {time_stamp}"
            elif 'tokenID' in tx:
                # NFT transaction
                token_name = tx.get('tokenName', 'Unknown')
                token_id = tx['tokenID']
                tx_summary = f"NFT Tx: {token_name}, Token ID: {token_id}, Hash: {tx_hash[:10]}..., Time: {time_stamp}"
            else:
                # Normal transaction
                value = int(tx['value']) / 1e18  # Convert wei to MATIC
                tx_summary = f"Tx: Value: {value} MATIC, Hash: {tx_hash[:10]}..., Time: {time_stamp}"
            self.transaction_listbox.insert(tk.END, tx_summary)

    def search_transactions(self):
        query = self.search_entry.get()
        if query:
            query = query.lower()
            # Search in all transactions
            filtered_transactions = []
            all_transactions = self.transactions + self.token_transactions + self.nft_transactions
            for tx in all_transactions:
                if (query in tx['hash'].lower()) or (query in tx['from'].lower()) or (query in tx['to'].lower()):
                    filtered_transactions.append(tx)
            self.display_filtered_transactions(filtered_transactions)
        else:
            messagebox.showerror("Error", "Please enter a search query.")

if __name__ == "__main__":
    app = AccountAnalyzerApp()
    app.mainloop()
