# supply_chain.py
import hashlib
import json
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64


class SupplyChainSystem:
    def __init__(self):
        self.chain = []
        self.products = {}

        self.participants = {
            'supplier_a': {'name': 'ABC Materials', 'role': 'supplier', 'password': self.hash('sup123')},
            'supplier_b': {'name': 'XYZ Components', 'role': 'supplier', 'password': self.hash('sup456')},
            'manufacturer': {'name': 'TechMakers Inc', 'role': 'manufacturer', 'password': self.hash('man123')},
            'distributor': {'name': 'Global Distributors', 'role': 'distributor', 'password': self.hash('dis123')},
            'retailer': {'name': 'MegaStore', 'role': 'retailer', 'password': self.hash('ret123')},
            'auditor': {'name': 'Quality Control Board', 'role': 'auditor', 'password': self.hash('aud123')}
        }

        # Generate keys for each participant
        self.participant_keys = {}
        for participant in self.participants:
            key = RSA.generate(2048)
            self.participant_keys[participant] = {
                'private': key,
                'public': key.publickey()
            }

        self.current_user = None

        # Create genesis block
        self._create_genesis_block()

    def hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def _create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = {
            'index': 0,
            'timestamp': datetime.now().isoformat(),
            'data': 'GENESIS BLOCK',
            'previous_hash': '0' * 64,
            'hash': self._calculate_block_hash(0, 'GENESIS BLOCK', '0' * 64),
            'signature': '',
            'participant': 'system'
        }
        self.chain.append(genesis_block)

    def _calculate_block_hash(self, index, data, previous_hash):
        """Calculate hash for a block"""
        block_string = f"{index}{data}{previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def login(self, username, password):
        if username in self.participants and self.participants[username]['password'] == self.hash(password):
            self.current_user = username
            return True
        return False

    def create_product(self, product_id, name, description):
        """Create a new product"""
        if self.participants[self.current_user]['role'] != 'supplier':
            return "Only suppliers can create products"

        if product_id in self.products:
            return "Product ID already exists"

        self.products[product_id] = {
            'id': product_id,
            'name': name,
            'description': description,
            'created_by': self.current_user,
            'created_at': datetime.now().isoformat(),
            'current_owner': self.current_user,
            'status': 'raw_materials',
            'history': []
        }

        # Create initial block
        self._add_to_chain({
            'action': 'CREATE_PRODUCT',
            'product_id': product_id,
            'name': name,
            'description': description
        })

        return f"Product {product_id} created"

    def transfer_product(self, product_id, to_participant):
        """Transfer product to another participant"""
        if product_id not in self.products:
            return "Product not found"

        product = self.products[product_id]

        # Check permissions
        if product['current_owner'] != self.current_user:
            return f"You don't own this product. Current owner: {product['current_owner']}"

        if to_participant not in self.participants:
            return "Invalid recipient"

        # Update product
        old_owner = product['current_owner']
        product['current_owner'] = to_participant

        # Update status based on new owner's role
        new_role = self.participants[to_participant]['role']
        if new_role == 'manufacturer':
            product['status'] = 'manufacturing'
        elif new_role == 'distributor':
            product['status'] = 'in_transit'
        elif new_role == 'retailer':
            product['status'] = 'in_stock'

        # Add to history
        transfer_record = {
            'from': old_owner,
            'to': to_participant,
            'timestamp': datetime.now().isoformat(),
            'by': self.current_user
        }
        product['history'].append(transfer_record)

        # Add to blockchain
        self._add_to_chain({
            'action': 'TRANSFER',
            'product_id': product_id,
            'from': old_owner,
            'to': to_participant,
            'status': product['status']
        })

        return f"Product {product_id} transferred from {old_owner} to {to_participant}"

    def update_status(self, product_id, status, notes=''):
        """Update product status"""
        if product_id not in self.products:
            return "Product not found"

        product = self.products[product_id]

        # Check if user owns the product
        if product['current_owner'] != self.current_user:
            return "You don't own this product"

        old_status = product['status']
        product['status'] = status

        # Add to blockchain
        self._add_to_chain({
            'action': 'STATUS_UPDATE',
            'product_id': product_id,
            'old_status': old_status,
            'new_status': status,
            'notes': notes
        })

        return f"Product {product_id} status updated: {old_status} -> {status}"

    def _add_to_chain(self, data):
        """Add a new block to the chain with digital signature"""
        previous_block = self.chain[-1]
        index = len(self.chain)

        # Create block
        block = {
            'index': index,
            'timestamp': datetime.now().isoformat(),
            'data': data,
            'previous_hash': previous_block['hash'],
            'participant': self.current_user
        }

        # Calculate hash
        block['hash'] = self._calculate_block_hash(
            block['index'],
            json.dumps(block['data']),
            block['previous_hash']
        )

        # Sign the block
        h = SHA256.new(json.dumps(block['data']).encode())
        signature = pkcs1_15.new(self.participant_keys[self.current_user]['private']).sign(h)
        block['signature'] = base64.b64encode(signature).decode()

        self.chain.append(block)

    def verify_chain(self):
        """Verify the integrity of the blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Verify hash
            calculated_hash = self._calculate_block_hash(
                current_block['index'],
                json.dumps(current_block['data']),
                current_block['previous_hash']
            )

            if current_block['hash'] != calculated_hash:
                return False, f"Hash mismatch at block {i}"

            # Verify link to previous block
            if current_block['previous_hash'] != previous_block['hash']:
                return False, f"Chain broken at block {i}"

            # Verify signature
            if current_block['participant'] != 'system':  # Skip genesis
                h = SHA256.new(json.dumps(current_block['data']).encode())
                signature = base64.b64decode(current_block['signature'])
                try:
                    participant_key = self.participant_keys[current_block['participant']]['public']
                    pkcs1_15.new(participant_key).verify(h, signature)
                except:
                    return False, f"Invalid signature at block {i}"

        return True, "Chain is valid"

    def track_product(self, product_id):
        """Track a product through the supply chain"""
        if product_id not in self.products:
            return "Product not found"

        product = self.products[product_id]

        print(f"\n🔍 TRACKING PRODUCT: {product_id}")
        print(f"Name: {product['name']}")
        print(f"Description: {product['description']}")
        print(f"Current Owner: {self.participants[product['current_owner']]['name']}")
        print(f"Status: {product['status']}")

        print("\n📋 TRANSFER HISTORY:")
        for record in product['history']:
            from_name = self.participants[record['from']]['name']
            to_name = self.participants[record['to']]['name']
            print(f"  {record['timestamp'][:19]}: {from_name} → {to_name}")

        # Find related blockchain entries
        print("\n⛓️ BLOCKCHAIN ENTRIES:")
        for block in self.chain:
            if block['participant'] != 'system' and 'product_id' in block['data']:
                if block['data']['product_id'] == product_id:
                    action = block['data']['action']
                    timestamp = block['timestamp'][:19]
                    participant = self.participants[block['participant']]['name']
                    print(f"  {timestamp} - {participant}: {action}")

    def view_chain(self, n=5):
        """View last n blocks of the chain"""
        print(f"\n⛓️ BLOCKCHAIN (Last {n} blocks):")
        print("=" * 60)

        for block in self.chain[-n:]:
            print(f"\nBlock #{block['index']}")
            print(f"Timestamp: {block['timestamp'][:19]}")
            print(f"Participant: {self.participants.get(block['participant'], {}).get('name', 'System')}")
            print(f"Action: {block['data'].get('action', 'GENESIS')}")
            print(f"Hash: {block['hash'][:20]}...")
            print(f"Prev Hash: {block['previous_hash'][:20]}...")

            if 'product_id' in block['data']:
                print(f"Product: {block['data']['product_id']}")


def main():
    supply_chain = SupplyChainSystem()

    print("🚚 SECURE SUPPLY CHAIN SYSTEM")
    print("=" * 60)
    print("Participants: supplier_a, supplier_b, manufacturer, distributor, retailer, auditor")
    print("Passwords: sup123, sup456, man123, dis123, ret123, aud123")

    # Login
    while True:
        print("\n🔐 Login")
        user = input("Username: ")
        pwd = input("Password: ")

        if supply_chain.login(user, pwd):
            participant = supply_chain.participants[user]
            print(f"✅ Welcome, {participant['name']} ({participant['role']})!")
            break
        else:
            print("❌ Invalid credentials")

    # Main menu
    while True:
        role = supply_chain.participants[supply_chain.current_user]['role']
        print(f"\n👤 {supply_chain.current_user} ({role})")
        print("\n1. Create Product (Suppliers only)")
        print("2. Transfer Product")
        print("3. Update Status")
        print("4. Track Product")
        print("5. View Blockchain")
        print("6. Verify Chain Integrity")
        print("7. My Products")
        print("8. Exit")

        choice = input("\nSelect option: ")

        if choice == '1':
            if role != 'supplier':
                print("❌ Only suppliers can create products")
            else:
                pid = input("Product ID: ")
                name = input("Product Name: ")
                desc = input("Description: ")
                result = supply_chain.create_product(pid, name, desc)
                print(result)

        elif choice == '2':
            pid = input("Product ID: ")
            print("\nAvailable participants:")
            for user_id, info in supply_chain.participants.items():
                if user_id != supply_chain.current_user:
                    print(f"  {user_id}: {info['name']}")

            to_user = input("\nTransfer to: ")
            result = supply_chain.transfer_product(pid, to_user)
            print(result)

        elif choice == '3':
            pid = input("Product ID: ")
            print("\nStatus options: raw_materials, manufacturing, quality_check, in_transit, in_stock, sold")
            status = input("New Status: ")
            notes = input("Notes (optional): ")
            result = supply_chain.update_status(pid, status, notes)
            print(result)

        elif choice == '4':
            pid = input("Product ID: ")
            supply_chain.track_product(pid)

        elif choice == '5':
            try:
                n = int(input("Number of blocks to show (default 5): ") or "5")
                supply_chain.view_chain(n)
            except:
                supply_chain.view_chain()

        elif choice == '6':
            if role != 'auditor':
                print("❌ Only auditors can verify chain integrity")
            else:
                valid, message = supply_chain.verify_chain()
                if valid:
                    print(f"✅ {message}")
                else:
                    print(f"❌ {message}")

        elif choice == '7':
            print("\n📦 MY PRODUCTS:")
            found = False
            for pid, product in supply_chain.products.items():
                if product['current_owner'] == supply_chain.current_user:
                    print(f"\n{pid}: {product['name']}")
                    print(f"  Status: {product['status']}")
                    print(f"  Created: {product['created_at'][:10]}")
                    found = True

            if not found:
                print("No products owned")

        elif choice == '8':
            print("👋 Goodbye!")
            break


if __name__ == "__main__":
    main()