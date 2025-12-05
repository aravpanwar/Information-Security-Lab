# hospital_system.py
#Features: Patient records, doctors, admin, audit logs, AES encryption, role-based access
import hashlib
import json
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


class HospitalSystem:
    def __init__(self):
        self.patients = {}
        self.medical_records = {}
        self.users = {
            'admin': {'password': self.hash('admin123'), 'role': 'admin'},
            'doctor1': {'password': self.hash('doc123'), 'role': 'doctor'},
            'doctor2': {'password': self.hash('doc456'), 'role': 'doctor'},
            'auditor': {'password': self.hash('audit123'), 'role': 'auditor'}
        }
        self.audit_log = []
        self.master_key = get_random_bytes(32)
        self.current_user = None

    def hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def encrypt_record(self, data):
        """Encrypt medical record using AES"""
        cipher = AES.new(self.master_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = cipher.iv
        return base64.b64encode(iv + ct_bytes).decode()

    def decrypt_record(self, enc_data):
        """Decrypt medical record"""
        enc_data = base64.b64decode(enc_data)
        iv = enc_data[:16]
        ct = enc_data[16:]
        cipher = AES.new(self.master_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()

    def login(self, username, password):
        if username in self.users and self.users[username]['password'] == self.hash(password):
            self.current_user = username
            self.log_audit(f"{username} logged in")
            return True
        return False

    def log_audit(self, action):
        entry = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'user': self.current_user,
            'action': action
        }
        self.audit_log.append(entry)

    def add_patient(self, patient_id, name, age):
        if self.users[self.current_user]['role'] in ['admin', 'doctor']:
            self.patients[patient_id] = {'name': name, 'age': age}
            self.log_audit(f"Added patient {patient_id}")
            return True
        return False

    def add_medical_record(self, patient_id, record):
        if self.users[self.current_user]['role'] in ['admin', 'doctor']:
            encrypted_record = self.encrypt_record(record)
            if patient_id not in self.medical_records:
                self.medical_records[patient_id] = []
            self.medical_records[patient_id].append(encrypted_record)
            self.log_audit(f"Added medical record for {patient_id}")
            return True
        return False

    def view_patient(self, patient_id):
        role = self.users[self.current_user]['role']

        if role in ['admin', 'doctor', 'auditor']:
            if patient_id in self.patients:
                patient = self.patients[patient_id]
                records = []

                if role in ['admin', 'doctor']:
                    # Doctors and admins can see decrypted records
                    if patient_id in self.medical_records:
                        records = [self.decrypt_record(r) for r in self.medical_records[patient_id]]
                else:
                    # Auditors only see that records exist (encrypted)
                    records = ["[ENCRYPTED]" for _ in self.medical_records.get(patient_id, [])]

                self.log_audit(f"Viewed patient {patient_id}")
                return {'patient': patient, 'records': records}
        return None

    def get_audit_log(self):
        if self.users[self.current_user]['role'] in ['admin', 'auditor']:
            return self.audit_log[-10:]  # Last 10 entries
        return []


def main():
    hospital = HospitalSystem()

    print("🏥 HOSPITAL MANAGEMENT SYSTEM")
    print("=" * 50)

    # Login
    while True:
        print("\n🔐 Login")
        user = input("Username: ")
        pwd = input("Password: ")

        if hospital.login(user, pwd):
            print(f"✅ Welcome, {user}!")
            break
        else:
            print("❌ Invalid credentials")

    # Main menu
    while True:
        role = hospital.users[hospital.current_user]['role']
        print(f"\n👤 Logged in as: {hospital.current_user} ({role})")
        print("\n1. Add Patient")
        print("2. Add Medical Record")
        print("3. View Patient")
        print("4. View Audit Log")
        print("5. Exit")

        choice = input("\nSelect option: ")

        if choice == '1':
            pid = input("Patient ID: ")
            name = input("Name: ")
            age = input("Age: ")
            if hospital.add_patient(pid, name, age):
                print("✅ Patient added")
            else:
                print("❌ Permission denied")

        elif choice == '2':
            pid = input("Patient ID: ")
            record = input("Medical Record: ")
            if hospital.add_medical_record(pid, record):
                print("✅ Record added (encrypted)")
            else:
                print("❌ Permission denied")

        elif choice == '3':
            pid = input("Patient ID: ")
            result = hospital.view_patient(pid)
            if result:
                print(f"\nPatient: {result['patient']['name']}, Age: {result['patient']['age']}")
                print("Medical Records:")
                for i, rec in enumerate(result['records'], 1):
                    print(f"  {i}. {rec}")
            else:
                print("❌ Patient not found or permission denied")

        elif choice == '4':
            logs = hospital.get_audit_log()
            print("\n📊 AUDIT LOG (Last 10 entries):")
            for log in logs:
                print(f"{log['timestamp']} - {log['user']}: {log['action']}")

        elif choice == '5':
            print("👋 Goodbye!")
            break


if __name__ == "__main__":
    main()