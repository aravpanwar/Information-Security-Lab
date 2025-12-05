# banking_system.py
#Features: Customers, tellers, managers, RSA signatures, transaction logging
import hashlib
import json
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64


class BankingSystem:
    def __init__(self):
        self.accounts = {
            'ACC001': {'name': 'John Doe', 'balance': 5000.0, 'pin': '1234'},
            'ACC002': {'name': 'Jane Smith', 'balance': 10000.0, 'pin': '5678'},
            'ACC003': {'name': 'Bob Wilson', 'balance': 7500.0, 'pin': '9012'}
        }

        self.transactions = []
        self.users = {
            'teller1': {'password': self.hash('teller123'), 'role': 'teller'},
            'teller2': {'password': self.hash('teller456'), 'role': 'teller'},
            'manager': {'password': self.hash('manager123'), 'role': 'manager'},
            'auditor': {'password': self.hash('auditor123'), 'role': 'auditor'}
        }

        # Generate RSA keys for digital signatures
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.current_user = None

    def hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def login(self, username, password):
        if username in self.users and self.users[username]['password'] == self.hash(password):
            self.current_user = username
            return True
        return False

    def verify_account(self, account_no, pin):
        return account_no in self.accounts and self.accounts[account_no]['pin'] == pin

    def sign_transaction(self, transaction_data):
        """Create digital signature for transaction"""
        h = SHA256.new(json.dumps(transaction_data).encode())
        signature = pkcs1_15.new(self.key).sign(h)
        return base64.b64encode(signature).decode()

    def verify_signature(self, transaction_data, signature):
        """Verify transaction signature"""
        h = SHA256.new(json.dumps(transaction_data).encode())
        try:
            pkcs1_15.new(self.public_key).verify(h, base64.b64decode(signature))
            return True
        except:
            return False

    def withdraw(self, account_no, amount):
        role = self.users[self.current_user]['role']

        if role not in ['teller', 'manager']:
            return "Permission denied"

        if account_no not in self.accounts:
            return "Account not found"

        if self.accounts[account_no]['balance'] < amount:
            return "Insufficient funds"

        # Create transaction record
        transaction = {
            'timestamp': datetime.now().isoformat(),
            'type': 'WITHDRAWAL',
            'account': account_no,
            'amount': amount,
            'teller': self.current_user,
            'previous_balance': self.accounts[account_no]['balance']
        }

        # Sign the transaction
        transaction['signature'] = self.sign_transaction(transaction)

        # Update balance
        self.accounts[account_no]['balance'] -= amount
        transaction['new_balance'] = self.accounts[account_no]['balance']

        self.transactions.append(transaction)

        # Verify signature (for demonstration)
        if self.verify_signature(transaction, transaction['signature']):
            return f"Withdrawal successful. New balance: ${self.accounts[account_no]['balance']:.2f}"
        else:
            return "Transaction signature invalid"

    def deposit(self, account_no, amount):
        role = self.users[self.current_user]['role']

        if role not in ['teller', 'manager']:
            return "Permission denied"

        if account_no not in self.accounts:
            return "Account not found"

        # Create transaction record
        transaction = {
            'timestamp': datetime.now().isoformat(),
            'type': 'DEPOSIT',
            'account': account_no,
            'amount': amount,
            'teller': self.current_user,
            'previous_balance': self.accounts[account_no]['balance']
        }

        # Sign the transaction
        transaction['signature'] = self.sign_transaction(transaction)

        # Update balance
        self.accounts[account_no]['balance'] += amount
        transaction['new_balance'] = self.accounts[account_no]['balance']

        self.transactions.append(transaction)

        return f"Deposit successful. New balance: ${self.accounts[account_no]['balance']:.2f}"

    def view_account(self, account_no):
        role = self.users[self.current_user]['role']

        if role not in ['teller', 'manager', 'auditor']:
            return None

        if account_no in self.accounts:
            account = self.accounts[account_no].copy()

            # Hide sensitive info from auditors
            if role == 'auditor':
                account['pin'] = '****'
                account['balance'] = '****'

            return account
        return None

    def view_transactions(self, account_no=None):
        role = self.users[self.current_user]['role']

        if role not in ['manager', 'auditor']:
            return []

        if account_no:
            # Filter transactions for specific account
            filtered = [t for t in self.transactions if t['account'] == account_no]
        else:
            # All transactions for managers/auditors
            filtered = self.transactions

        # For auditors, hide amounts and only show verification status
        if role == 'auditor':
            for t in filtered:
                t['amount'] = '****'
                t['previous_balance'] = '****'
                t['new_balance'] = '****'
                # Show signature verification status
                t['signature_valid'] = self.verify_signature(t, t['signature'])

        return filtered[-10:]  # Last 10 transactions


def main():
    bank = BankingSystem()

    print("🏦 SECURE BANKING SYSTEM")
    print("=" * 50)

    # Login
    while True:
        print("\n🔐 Employee Login")
        user = input("Username: ")
        pwd = input("Password: ")

        if bank.login(user, pwd):
            print(f"✅ Welcome, {user}!")
            break
        else:
            print("❌ Invalid credentials")

    # Main menu
    while True:
        role = bank.users[bank.current_user]['role']
        print(f"\n👤 Role: {role}")
        print("\n1. Customer Withdrawal")
        print("2. Customer Deposit")
        print("3. View Account")
        print("4. View Transactions")
        print("5. Verify Transaction Signatures")
        print("6. Exit")

        choice = input("\nSelect option: ")

        if choice == '1':
            acc = input("Account Number: ")
            pin = input("PIN: ")
            if bank.verify_account(acc, pin):
                try:
                    amount = float(input("Amount: $"))
                    result = bank.withdraw(acc, amount)
                    print(f"✅ {result}")
                except:
                    print("❌ Invalid amount")
            else:
                print("❌ Invalid account or PIN")

        elif choice == '2':
            acc = input("Account Number: ")
            pin = input("PIN: ")
            if bank.verify_account(acc, pin):
                try:
                    amount = float(input("Amount: $"))
                    result = bank.deposit(acc, amount)
                    print(f"✅ {result}")
                except:
                    print("❌ Invalid amount")
            else:
                print("❌ Invalid account or PIN")

        elif choice == '3':
            acc = input("Account Number: ")
            account = bank.view_account(acc)
            if account:
                print(f"\nAccount: {acc}")
                print(f"Name: {account['name']}")
                print(f"Balance: ${account['balance']}")
                if role != 'auditor':
                    print(f"PIN: {account['pin']}")
            else:
                print("❌ Account not found or permission denied")

        elif choice == '4':
            acc = input("Account Number (or Enter for all): ")
            if acc:
                transactions = bank.view_transactions(acc)
            else:
                transactions = bank.view_transactions()

            print(f"\n📋 TRANSACTIONS:")
            for t in transactions:
                print(f"\nDate: {t['timestamp'][:19]}")
                print(f"Type: {t['type']}")
                print(f"Account: {t['account']}")
                print(f"Amount: ${t['amount']}")
                print(f"Teller: {t['teller']}")
                if role == 'auditor':
                    print(f"Signature Valid: {t.get('signature_valid', 'N/A')}")

        elif choice == '5':
            if role == 'auditor':
                print("\n🔐 VERIFYING TRANSACTION SIGNATURES")
                for t in bank.transactions[-5:]:  # Check last 5
                    valid = bank.verify_signature(t, t['signature'])
                    status = "✅ VALID" if valid else "❌ INVALID"
                    print(f"{t['timestamp'][:19]} - {t['type']} - {status}")
            else:
                print("❌ Auditors only")

        elif choice == '6':
            print("👋 Goodbye!")
            break


if __name__ == "__main__":
    main()