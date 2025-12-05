# healthcare_iot.py
"""
HEALTHCARE IOT SECURITY SYSTEM - HYBRID CRYPTOGRAPHY
====================================================
Concepts Used:
1. Hybrid Encryption (RSA + AES) - Patient data encryption
2. SHA-256 Hashing - Data integrity for medical readings
3. Digital Certificates - Device authentication
4. Real-time Encryption - Continuous data protection
5. Multi-layer Security - Device, Gateway, Cloud
6. Role-Based Access - Doctor, Nurse, Patient, Admin
"""

import hashlib
import json
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import random
import time


class HealthcareIoTSystem:
    def __init__(self):
        # System roles and devices
        self.roles = {
            'patient1': {'password': self.hash('pat123'), 'role': 'patient', 'devices': ['device001']},
            'patient2': {'password': self.hash('pat456'), 'role': 'patient', 'devices': ['device002']},
            'nurse1': {'password': self.hash('nur123'), 'role': 'nurse', 'ward': 'ICU'},
            'nurse2': {'password': self.hash('nur456'), 'role': 'nurse', 'ward': 'General'},
            'doctor1': {'password': self.hash('doc123'), 'role': 'doctor', 'specialty': 'Cardiology'},
            'doctor2': {'password': self.hash('doc456'), 'role': 'doctor', 'specialty': 'Neurology'},
            'admin': {'password': self.hash('admin123'), 'role': 'admin'}
        }

        # IoT Medical Devices
        self.devices = {
            'device001': {
                'type': 'heart_monitor',
                'patient': 'patient1',
                'public_key': None,
                'status': 'active',
                'last_reading': None
            },
            'device002': {
                'type': 'blood_pressure',
                'patient': 'patient2',
                'public_key': None,
                'status': 'active',
                'last_reading': None
            },
            'device003': {
                'type': 'glucose_monitor',
                'patient': 'patient1',
                'public_key': None,
                'status': 'inactive',
                'last_reading': None
            }
        }

        # Generate RSA keys for devices
        for device_id in self.devices:
            key = RSA.generate(1024)  # Smaller keys for IoT devices
            self.devices[device_id]['public_key'] = key.publickey()
            self.devices[device_id]['private_key'] = key

        # Generate RSA keys for users
        self.user_keys = {}
        for user in self.roles:
            key = RSA.generate(2048)
            self.user_keys[user] = {
                'public': key.publickey(),
                'private': key
            }

        # Medical data storage
        self.patient_data = {}  # patient_id -> list of encrypted readings
        self.alerts = []  # Security alerts
        self.audit_log = []

        # Session management
        self.session_keys = {}  # device_id -> AES session key

        self.current_user = None

    def hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def log_audit(self, action, device=None):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'user': self.current_user,
            'role': self.roles[self.current_user]['role'],
            'action': action,
            'device': device
        }
        self.audit_log.append(entry)

    def login(self, username, password):
        if username in self.roles and self.roles[username]['password'] == self.hash(password):
            self.current_user = username
            self.log_audit('LOGIN')
            return True
        return False

    # ========== MODULE 1: DEVICE AUTHENTICATION & KEY EXCHANGE ==========
    def authenticate_device(self, device_id):
        """Authenticate IoT device using digital certificate (simplified)"""
        if device_id not in self.devices:
            return "Device not registered"

        # Create device certificate
        cert_data = {
            'device_id': device_id,
            'device_type': self.devices[device_id]['type'],
            'patient': self.devices[device_id]['patient'],
            'timestamp': datetime.now().isoformat(),
            'expiry': '2025-12-31'
        }

        # Sign certificate with system key
        h = SHA256.new(json.dumps(cert_data).encode())
        signature = pkcs1_15.new(self.user_keys['admin']['private']).sign(h)

        certificate = {
            'data': cert_data,
            'signature': base64.b64encode(signature).decode()
        }

        # Generate session key for this device
        session_key = get_random_bytes(32)
        self.session_keys[device_id] = session_key

        # Encrypt session key with device's public key
        cipher = PKCS1_OAEP.new(self.devices[device_id]['public_key'])
        encrypted_key = cipher.encrypt(session_key)

        self.log_audit('DEVICE_AUTH', device_id)

        return {
            'certificate': certificate,
            'encrypted_session_key': base64.b64encode(encrypted_key).decode(),
            'status': 'authenticated'
        }

    def verify_device_certificate(self, device_id):
        """Verify device certificate"""
        if device_id not in self.devices:
            return "Device not found"

        # For demo, create and verify on the fly
        cert_data = {
            'device_id': device_id,
            'device_type': self.devices[device_id]['type'],
            'patient': self.devices[device_id]['patient'],
            'timestamp': datetime.now().isoformat()
        }

        h = SHA256.new(json.dumps(cert_data).encode())
        signature = pkcs1_15.new(self.user_keys['admin']['private']).sign(h)

        # Verify
        h_verify = SHA256.new(json.dumps(cert_data).encode())
        try:
            pkcs1_15.new(self.user_keys['admin']['public']).verify(h_verify, signature)
            return f"✅ Device {device_id} certificate VALID"
        except:
            return f"❌ Device {device_id} certificate INVALID"

    # ========== MODULE 2: SECURE DATA TRANSMISSION (HYBRID ENCRYPTION) ==========
    def send_medical_reading(self, device_id, reading_type, value):
        """Send encrypted medical reading from IoT device"""
        if device_id not in self.devices:
            return "Device not found"

        if device_id not in self.session_keys:
            return "Device not authenticated"

        # Prepare reading data
        reading = {
            'device_id': device_id,
            'type': reading_type,
            'value': value,
            'timestamp': datetime.now().isoformat(),
            'patient': self.devices[device_id]['patient']
        }

        # Compute hash for integrity
        reading_hash = hashlib.sha256(json.dumps(reading).encode()).hexdigest()
        reading['integrity_hash'] = reading_hash

        # Encrypt with AES session key (symmetric)
        session_key = self.session_keys[device_id]
        cipher = AES.new(session_key, AES.MODE_CBC)

        reading_json = json.dumps(reading)
        ct_bytes = cipher.encrypt(pad(reading_json.encode(), AES.block_size))

        encrypted_reading = {
            'iv': base64.b64encode(cipher.iv).decode(),
            'ciphertext': base64.b64encode(ct_bytes).decode(),
            'device_id': device_id
        }

        # Store in patient data
        patient_id = self.devices[device_id]['patient']
        if patient_id not in self.patient_data:
            self.patient_data[patient_id] = []

        self.patient_data[patient_id].append(encrypted_reading)
        self.devices[device_id]['last_reading'] = datetime.now().isoformat()

        self.log_audit('DATA_TRANSMIT', device_id)

        # Simulate real-time monitoring
        self._check_alert_conditions(patient_id, reading_type, value)

        return {
            'status': 'transmitted',
            'encrypted_size': len(ct_bytes),
            'hash': reading_hash[:20] + '...'
        }

    def _check_alert_conditions(self, patient_id, reading_type, value):
        """Check for alert conditions"""
        alert_ranges = {
            'heart_rate': {'min': 60, 'max': 100},
            'blood_pressure_sys': {'min': 90, 'max': 140},
            'blood_pressure_dia': {'min': 60, 'max': 90},
            'glucose': {'min': 70, 'max': 140}
        }

        if reading_type in alert_ranges:
            rng = alert_ranges[reading_type]
            try:
                val = float(value)
                if val < rng['min'] or val > rng['max']:
                    alert = {
                        'patient': patient_id,
                        'type': reading_type,
                        'value': val,
                        'timestamp': datetime.now().isoformat(),
                        'message': f'{reading_type} out of range: {val}'
                    }
                    self.alerts.append(alert)
                    print(f"\n🚨 ALERT: {alert['message']}")
            except:
                pass

    # ========== MODULE 3: DATA ACCESS WITH ROLE-BASED DECRYPTION ==========
    def view_patient_data(self, patient_id, decrypt=False):
        """View patient data with role-based access control"""
        role = self.roles[self.current_user]['role']

        # Check permissions
        if role == 'patient' and self.current_user != patient_id:
            return "Patients can only view their own data"

        if patient_id not in self.patient_data:
            return "No data available"

        data_summary = {
            'patient': patient_id,
            'total_readings': len(self.patient_data[patient_id]),
            'latest_readings': []
        }

        # Get last 5 readings
        recent_data = self.patient_data[patient_id][-5:]

        for enc_reading in recent_data:
            device_id = enc_reading['device_id']

            if decrypt and device_id in self.session_keys:
                # Decrypt the reading
                session_key = self.session_keys[device_id]
                iv = base64.b64decode(enc_reading['iv'])
                ciphertext = base64.b64decode(enc_reading['ciphertext'])

                cipher = AES.new(session_key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
                reading = json.loads(decrypted)

                # Verify integrity
                original_hash = reading.pop('integrity_hash', '')
                current_hash = hashlib.sha256(json.dumps(reading).encode()).hexdigest()

                integrity = "✅ OK" if original_hash == current_hash else "❌ TAMPERED"

                data_summary['latest_readings'].append({
                    'device': device_id,
                    'type': reading['type'],
                    'value': reading['value'],
                    'time': reading['timestamp'][11:19],
                    'integrity': integrity,
                    'decrypted': True
                })
            else:
                # Show encrypted info only
                data_summary['latest_readings'].append({
                    'device': device_id,
                    'status': 'ENCRYPTED',
                    'time': 'N/A',
                    'integrity': '🔐 ENCRYPTED',
                    'decrypted': False
                })

        self.log_audit('VIEW_DATA', patient_id)
        return data_summary

    def emergency_access(self, patient_id, reason):
        """Emergency access override (doctors only)"""
        if self.roles[self.current_user]['role'] != 'doctor':
            return "Doctors only"

        # Log emergency access
        emergency_log = {
            'doctor': self.current_user,
            'patient': patient_id,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }

        # Sign emergency access
        h = SHA256.new(json.dumps(emergency_log).encode())
        signature = pkcs1_15.new(self.user_keys[self.current_user]['private']).sign(h)
        emergency_log['signature'] = base64.b64encode(signature).decode()

        self.alerts.append({
            'type': 'emergency_access',
            'data': emergency_log,
            'timestamp': datetime.now().isoformat()
        })

        # Grant temporary access
        print(f"\n⚠️ EMERGENCY ACCESS GRANTED")
        print(f"Doctor: {self.current_user}")
        print(f"Patient: {patient_id}")
        print(f"Reason: {reason}")
        print(f"Time: {datetime.now().strftime('%H:%M:%S')}")

        return emergency_log

    # ========== MODULE 4: REAL-TIME MONITORING SIMULATION ==========
    def simulate_device_readings(self, duration_seconds=30):
        """Simulate real-time IoT device readings"""
        print(f"\n📡 SIMULATING IOT DEVICE READINGS ({duration_seconds} seconds)...")
        print("Press Ctrl+C to stop\n")

        try:
            for i in range(duration_seconds):
                # Simulate readings from active devices
                for device_id, device in self.devices.items():
                    if device['status'] == 'active':
                        # Generate random readings based on device type
                        if device['type'] == 'heart_monitor':
                            value = random.randint(60, 120)
                            reading_type = 'heart_rate'
                        elif device['type'] == 'blood_pressure':
                            value = f"{random.randint(100, 140)}/{random.randint(60, 90)}"
                            reading_type = 'blood_pressure'
                        elif device['type'] == 'glucose_monitor':
                            value = random.randint(70, 180)
                            reading_type = 'glucose'
                        else:
                            continue

                        # Send encrypted reading
                        result = self.send_medical_reading(device_id, reading_type, value)

                        if i % 5 == 0:  # Show progress every 5 seconds
                            print(f"  {device_id}: {reading_type} = {value} | {result['status']}")

                time.sleep(1)  # Simulate 1-second intervals

            print(f"\n✅ Simulation complete")
            print(f"Total readings transmitted: {sum(len(d) for d in self.patient_data.values())}")

        except KeyboardInterrupt:
            print("\n⏹️ Simulation stopped")

    # ========== MODULE 5: SECURITY AUDIT & MONITORING ==========
    def security_report(self):
        """Generate security report"""
        if self.roles[self.current_user]['role'] != 'admin':
            return "Admin only"

        report = {
            'devices': {
                'total': len(self.devices),
                'active': len([d for d in self.devices.values() if d['status'] == 'active']),
                'authenticated': len(self.session_keys)
            },
            'data': {
                'total_readings': sum(len(d) for d in self.patient_data.values()),
                'patients_with_data': len(self.patient_data)
            },
            'security': {
                'active_alerts': len(self.alerts),
                'audit_entries': len(self.audit_log),
                'encryption_status': 'ACTIVE'
            }
        }

        return report

    def view_alerts(self):
        """View security and medical alerts"""
        role = self.roles[self.current_user]['role']

        if role not in ['doctor', 'nurse', 'admin']:
            return "Medical staff only"

        if not self.alerts:
            return "No alerts"

        recent_alerts = self.alerts[-10:]  # Last 10 alerts

        print(f"\n🚨 RECENT ALERTS ({len(recent_alerts)}):")
        for alert in recent_alerts:
            if 'type' in alert and alert['type'] == 'emergency_access':
                print(f"\n⚠️ EMERGENCY ACCESS:")
                data = alert['data']
                print(f"  Doctor: {data['doctor']}")
                print(f"  Patient: {data['patient']}")
                print(f"  Time: {data['timestamp'][11:19]}")
            else:
                print(f"\n📊 MEDICAL ALERT:")
                print(f"  Patient: {alert.get('patient', 'Unknown')}")
                print(f"  Type: {alert.get('type', 'Unknown')}")
                print(f"  Value: {alert.get('value', 'N/A')}")
                print(f"  Time: {alert.get('timestamp', 'N/A')[11:19]}")


def main():
    iot = HealthcareIoTSystem()

    print("🏥 HEALTHCARE IOT SECURITY SYSTEM")
    print("=" * 60)
    print("Hybrid Cryptography: RSA + AES + SHA-256 + Digital Signatures")
    print("\nRoles: patient, nurse, doctor, admin")
    print("Users: patient1, patient2, nurse1, nurse2, doctor1, doctor2, admin")
    print("Passwords: pat123, pat456, nur123, nur456, doc123, doc456, admin123")
    print("\nDevices: device001 (heart), device002 (BP), device003 (glucose)")

    # Login
    while True:
        print("\n" + "=" * 40)
        user = input("Username: ")
        pwd = input("Password: ")

        if iot.login(user, pwd):
            role = iot.roles[user]['role']
            print(f"\n✅ Welcome, {user} ({role})!")
            break
        else:
            print("❌ Invalid credentials")

    # Main menu
    while True:
        user_info = iot.roles[iot.current_user]
        role = user_info['role']

        print(f"\n🏥 {iot.current_user.upper()} - {role.upper()}")
        print("-" * 40)

        # Common options
        print("1. View Patient Data")
        print("2. View Security Alerts")

        # Role-specific options
        if role == 'admin':
            print("3. Authenticate Device")
            print("4. Verify Device Certificate")
            print("5. Security Report")
            print("6. Simulate IoT Readings")
            print("7. View Audit Log")

        elif role == 'doctor':
            print("3. Emergency Access")
            print("4. Monitor Patients")
            print("5. Verify Data Integrity")
            print("6. Simulate IoT Readings")

        elif role == 'nurse':
            print("3. Monitor Patients")
            print("4. Check Device Status")

        elif role == 'patient':
            print("3. My Medical Data")
            print("4. My Devices")

        print("0. Logout")

        choice = input("\nSelect: ")

        if choice == '0':
            print("👋 Logging out...")
            break

        # Common functions
        if choice == '1':
            if role == 'patient':
                patient_id = iot.current_user
            else:
                patient_id = input("Patient ID: ")

            decrypt = input("Decrypt data? (y/n): ").lower() == 'y'
            result = iot.view_patient_data(patient_id, decrypt)

            if isinstance(result, dict):
                print(f"\n📊 PATIENT DATA: {result['patient']}")
                print(f"Total readings: {result['total_readings']}")
                print(f"\nLatest readings:")
                for reading in result['latest_readings']:
                    if reading['decrypted']:
                        print(
                            f"  {reading['time']} - {reading['device']}: {reading['type']} = {reading['value']} {reading['integrity']}")
                    else:
                        print(f"  {reading['device']}: {reading['status']} {reading['integrity']}")
            else:
                print(result)

        elif choice == '2':
            if role in ['doctor', 'nurse', 'admin']:
                iot.view_alerts()
            else:
                print("Medical staff only")

        # Admin functions
        elif choice == '3' and role == 'admin':
            device_id = input("Device ID to authenticate: ")
            result = iot.authenticate_device(device_id)

            if isinstance(result, dict):
                print(f"\n✅ DEVICE AUTHENTICATED: {device_id}")
                print(f"Status: {result['status']}")
                print(f"Certificate issued")
                print(f"Session key exchanged (encrypted)")
            else:
                print(result)

        elif choice == '4' and role == 'admin':
            device_id = input("Device ID to verify: ")
            result = iot.verify_device_certificate(device_id)
            print(f"\n{result}")

        elif choice == '5' and role == 'admin':
            report = iot.security_report()
            print(f"\n🛡️ SECURITY REPORT:")
            print(f"\nDevices:")
            print(f"  Total: {report['devices']['total']}")
            print(f"  Active: {report['devices']['active']}")
            print(f"  Authenticated: {report['devices']['authenticated']}")
            print(f"\nData:")
            print(f"  Total readings: {report['data']['total_readings']}")
            print(f"  Patients with data: {report['data']['patients_with_data']}")
            print(f"\nSecurity:")
            print(f"  Active alerts: {report['security']['active_alerts']}")
            print(f"  Audit entries: {report['security']['audit_entries']}")
            print(f"  Encryption: {report['security']['encryption_status']}")

        elif choice == '6' and role in ['admin', 'doctor']:
            try:
                duration = int(input("Simulation duration (seconds): "))
                iot.simulate_device_readings(duration)
            except:
                print("Invalid duration")

        elif choice == '7' and role == 'admin':
            print(f"\n📋 AUDIT LOG ({len(iot.audit_log)} entries):")
            for entry in iot.audit_log[-10:]:
                time = entry['timestamp'][11:19]
                print(f"  {time} - {entry['user']}: {entry['action']}")

        # Doctor functions
        elif choice == '3' and role == 'doctor':
            patient_id = input("Patient ID for emergency access: ")
            reason = input("Reason for emergency access: ")
            result = iot.emergency_access(patient_id, reason)
            if isinstance(result, dict):
                print(f"\nEmergency access logged and signed")

        elif choice == '4' and role == 'doctor':
            print("\n👨‍⚕️ ACTIVE PATIENT MONITORING")
            for patient_id in iot.patient_data:
                print(f"\nPatient: {patient_id}")
                data = iot.view_patient_data(patient_id, False)
                if isinstance(data, dict):
                    print(f"  Readings: {data['total_readings']}")
                    if data['latest_readings']:
                        latest = data['latest_readings'][-1]
                        print(f"  Latest: {latest.get('type', 'N/A')} at {latest.get('time', 'N/A')}")

        elif choice == '5' and role == 'doctor':
            print("\n🔍 DATA INTEGRITY CHECK")
            for patient_id in iot.patient_data:
                data = iot.view_patient_data(patient_id, True)
                if isinstance(data, dict):
                    valid = sum(1 for r in data['latest_readings'] if r.get('integrity') == '✅ OK')
                    total = len(data['latest_readings'])
                    print(f"  {patient_id}: {valid}/{total} readings integrity OK")

        # Nurse functions
        elif choice == '3' and role == 'nurse':
            print("\n👩‍⚕️ PATIENT MONITORING")
            for patient_id in iot.patient_data:
                data = iot.view_patient_data(patient_id, False)
                if isinstance(data, dict) and data['total_readings'] > 0:
                    print(f"  {patient_id}: {data['total_readings']} readings")

        elif choice == '4' and role == 'nurse':
            print("\n📱 DEVICE STATUS:")
            for device_id, device in iot.devices.items():
                status = "🟢" if device['status'] == 'active' else "🔴"
                last = device.get('last_reading', 'Never')
                print(f"  {device_id}: {device['type']} {status} Last: {last[11:19] if last != 'Never' else 'Never'}")

        # Patient functions
        elif choice == '3' and role == 'patient':
            patient_id = iot.current_user
            data = iot.view_patient_data(patient_id, True)

            if isinstance(data, dict):
                print(f"\n📋 MY MEDICAL DATA:")
                print(f"Total readings: {data['total_readings']}")
                if data['latest_readings']:
                    print(f"\nRecent readings:")
                    for reading in data['latest_readings']:
                        if reading['decrypted']:
                            print(f"  {reading['time']}: {reading['type']} = {reading['value']}")
                        else:
                            print(f"  {reading['device']}: Encrypted")
            else:
                print(data)

        elif choice == '4' and role == 'patient':
            patient_id = iot.current_user
            print(f"\n📱 MY DEVICES:")
            for device_id, device in iot.devices.items():
                if device['patient'] == patient_id:
                    status = "Active" if device['status'] == 'active' else "Inactive"
                    print(f"  {device_id}: {device['type']} - {status}")


if __name__ == "__main__":
    main()