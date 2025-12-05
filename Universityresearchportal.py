# university_research.py
"""
UNIVERSITY RESEARCH PORTAL - ADVANCED CRYPTOGRAPHY SYSTEM
=========================================================
Concepts Used:
1. Searchable Encryption (SSE) - Encrypted research paper search
2. Homomorphic Encryption (Paillier) - Secure data analysis
3. RSA Digital Signatures - Paper authorship verification
4. AES - Document encryption
5. Hashing - Data integrity
6. Multi-role system (Student, Researcher, Professor, Admin)
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


class UniversityResearchPortal:
    def __init__(self):
        # User roles and permissions
        self.users = {
            'student1': {'password': self.hash('stu123'), 'role': 'student', 'department': 'CS'},
            'student2': {'password': self.hash('stu456'), 'role': 'student', 'department': 'Math'},
            'researcher1': {'password': self.hash('res123'), 'role': 'researcher', 'department': 'CS'},
            'researcher2': {'password': self.hash('res456'), 'role': 'researcher', 'department': 'Physics'},
            'professor1': {'password': self.hash('prof123'), 'role': 'professor', 'department': 'CS'},
            'professor2': {'password': self.hash('prof456'), 'role': 'professor', 'department': 'Math'},
            'admin': {'password': self.hash('admin123'), 'role': 'admin'}
        }

        # Generate RSA keys for signing
        self.user_keys = {}
        for user in self.users:
            key = RSA.generate(2048)
            self.user_keys[user] = {
                'private': key,
                'public': key.publickey()
            }

        # Research papers database (encrypted)
        self.research_papers = []
        self.encrypted_index = {}  # For searchable encryption

        # Secure data for homomorphic analysis
        self.research_data = {}  # Encrypted research data

        # Paillier keys for homomorphic encryption
        self.paillier_keys = self._generate_paillier_keys()

        self.current_user = None
        self.audit_log = []

    def _generate_paillier_keys(self):
        """Generate simplified Paillier keys for demo"""
        # For real implementation, use proper Paillier
        return {'n': 3233, 'g': 3234}  # Simplified

    def hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def log_audit(self, action):
        self.audit_log.append({
            'timestamp': datetime.now().isoformat(),
            'user': self.current_user,
            'action': action
        })

    def login(self, username, password):
        if username in self.users and self.users[username]['password'] == self.hash(password):
            self.current_user = username
            self.log_audit('LOGIN')
            return True
        return False

    # ========== MODULE 1: PAPER SUBMISSION (AES + Digital Signatures) ==========
    def submit_research_paper(self, title, abstract, content, keywords):
        """Submit encrypted research paper with digital signature"""
        role = self.users[self.current_user]['role']

        if role not in ['researcher', 'professor']:
            return "Only researchers and professors can submit papers"

        # Generate AES key for this paper
        paper_key = get_random_bytes(32)

        # Encrypt content
        cipher = AES.new(paper_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(content.encode(), AES.block_size))
        encrypted_content = {
            'iv': base64.b64encode(cipher.iv).decode(),
            'ciphertext': base64.b64encode(ct_bytes).decode()
        }

        # Create digital signature
        signature_data = {
            'title': title,
            'author': self.current_user,
            'timestamp': datetime.now().isoformat(),
            'abstract_hash': self.hash(abstract)
        }

        h = SHA256.new(json.dumps(signature_data).encode())
        signature = pkcs1_15.new(self.user_keys[self.current_user]['private']).sign(h)

        # Create paper record
        paper = {
            'id': f"PAPER{len(self.research_papers) + 1:04d}",
            'title': title,
            'abstract': abstract,  # Abstract is not encrypted (for searching)
            'encrypted_content': encrypted_content,
            'encrypted_key': self._encrypt_with_rsa(paper_key),  # Encrypt AES key with RSA
            'author': self.current_user,
            'department': self.users[self.current_user]['department'],
            'keywords': [k.strip().lower() for k in keywords.split(',')],
            'signature': base64.b64encode(signature).decode(),
            'signature_data': signature_data,
            'submission_date': datetime.now().isoformat(),
            'status': 'submitted',
            'reviews': []
        }

        self.research_papers.append(paper)

        # Add to searchable index
        self._add_to_search_index(paper)

        self.log_audit(f'PAPER_SUBMIT: {paper["id"]}')
        return f"Paper {paper['id']} submitted and encrypted"

    def _encrypt_with_rsa(self, data):
        """Encrypt data with university's public RSA key"""
        # In real system, use proper key management
        return base64.b64encode(data).decode()  # Simplified for demo

    # ========== MODULE 2: SEARCHABLE ENCRYPTION (SSE) ==========
    def _add_to_search_index(self, paper):
        """Add paper to searchable encrypted index"""
        for keyword in paper['keywords']:
            # Create encrypted keyword
            keyword_hash = hashlib.sha256(keyword.encode()).digest()

            # Simple encryption for demo (in real SSE, use proper encryption)
            encrypted_keyword = base64.b64encode(keyword_hash).decode()

            if encrypted_keyword not in self.encrypted_index:
                self.encrypted_index[encrypted_keyword] = []

            self.encrypted_index[encrypted_keyword].append(paper['id'])

    def search_papers(self, query):
        """Search papers using searchable encryption"""
        query = query.lower().strip()

        # Encrypt search query (same as indexing)
        query_hash = hashlib.sha256(query.encode()).digest()
        encrypted_query = base64.b64encode(query_hash).decode()

        matching_papers = []

        if encrypted_query in self.encrypted_index:
            paper_ids = self.encrypted_index[encrypted_query]
            for paper_id in paper_ids:
                for paper in self.research_papers:
                    if paper['id'] == paper_id:
                        matching_papers.append(paper)

        self.log_audit(f'SEARCH: "{query}" -> {len(matching_papers)} results')
        return matching_papers

    # ========== MODULE 3: HOMOMORPHIC DATA ANALYSIS ==========
    def submit_research_data(self, data_points, analysis_type):
        """Submit encrypted research data for homomorphic analysis"""
        role = self.users[self.current_user]['role']

        if role not in ['researcher', 'professor']:
            return "Only researchers and professors can submit data"

        # Encrypt each data point (simplified Paillier)
        encrypted_data = []
        for point in data_points:
            # For demo, use simplified encryption
            encrypted = (point * self.paillier_keys['g']) % self.paillier_keys['n']
            encrypted_data.append(encrypted)

        data_id = f"DATA{len(self.research_data) + 1:04d}"
        self.research_data[data_id] = {
            'owner': self.current_user,
            'analysis_type': analysis_type,
            'encrypted_points': encrypted_data,
            'original_count': len(data_points),
            'submission_date': datetime.now().isoformat()
        }

        # Demonstrate homomorphic addition
        if analysis_type == 'sum':
            # Homomorphically compute sum
            homomorphic_sum = 0
            for enc_point in encrypted_data:
                homomorphic_sum = (homomorphic_sum + enc_point) % self.paillier_keys['n']

            print(f"\n🔢 HOMOMORPHIC ANALYSIS DEMO:")
            print(f"Data ID: {data_id}")
            print(f"Encrypted points: {len(encrypted_data)}")
            print(f"Homomorphic sum (encrypted): {homomorphic_sum}")

            # For demo, show what actual sum would be
            actual_sum = sum(data_points)
            print(f"Actual sum (if decrypted): {actual_sum}")

        self.log_audit(f'DATA_SUBMIT: {data_id}')
        return f"Research data {data_id} submitted for {analysis_type}"

    def collaborative_analysis(self, data_ids):
        """Combine multiple encrypted datasets for analysis"""
        role = self.users[self.current_user]['role']

        if role not in ['professor', 'admin']:
            return "Professors and admins only"

        combined_data = []
        sources = []

        for data_id in data_ids:
            if data_id in self.research_data:
                data = self.research_data[data_id]
                combined_data.extend(data['encrypted_points'])
                sources.append({
                    'id': data_id,
                    'owner': data['owner'],
                    'count': len(data['encrypted_points'])
                })

        if not combined_data:
            return "No valid data found"

        # Homomorphic average calculation (simplified)
        total_encrypted = 0
        for point in combined_data:
            total_encrypted = (total_encrypted + point) % self.paillier_keys['n']

        total_points = sum(s['count'] for s in sources)

        print(f"\n🤝 COLLABORATIVE ANALYSIS:")
        print(f"Combined {len(sources)} datasets")
        print(f"Total points: {total_points}")
        print(f"Homomorphic total (encrypted): {total_encrypted}")
        print("\nData Sources:")
        for source in sources:
            print(f"  {source['id']} - {source['owner']} ({source['count']} points)")

        return f"Analysis complete on {total_points} encrypted data points"

    # ========== MODULE 4: PAPER REVIEW & VERIFICATION ==========
    def review_paper(self, paper_id, review_score, comments):
        """Review paper with digital signature"""
        role = self.users[self.current_user]['role']

        if role != 'professor':
            return "Only professors can review papers"

        paper = None
        for p in self.research_papers:
            if p['id'] == paper_id:
                paper = p
                break

        if not paper:
            return "Paper not found"

        # Create review with signature
        review_data = {
            'paper_id': paper_id,
            'reviewer': self.current_user,
            'score': review_score,
            'timestamp': datetime.now().isoformat()
        }

        h = SHA256.new(json.dumps(review_data).encode())
        signature = pkcs1_15.new(self.user_keys[self.current_user]['private']).sign(h)

        review = {
            'reviewer': self.current_user,
            'score': review_score,
            'comments': comments,
            'signature': base64.b64encode(signature).decode(),
            'review_data': review_data,
            'date': datetime.now().isoformat()
        }

        paper['reviews'].append(review)
        paper['status'] = 'reviewed'

        self.log_audit(f'PAPER_REVIEW: {paper_id}')
        return f"Paper {paper_id} reviewed by {self.current_user}"

    def verify_paper_signature(self, paper_id):
        """Verify paper author's signature"""
        paper = None
        for p in self.research_papers:
            if p['id'] == paper_id:
                paper = p
                break

        if not paper:
            return "Paper not found"

        # Verify author signature
        h = SHA256.new(json.dumps(paper['signature_data']).encode())
        signature = base64.b64decode(paper['signature'])

        try:
            author_key = self.user_keys[paper['author']]['public']
            pkcs1_15.new(author_key).verify(h, signature)
            author_status = f"✅ Author ({paper['author']}): VALID"
        except:
            author_status = f"❌ Author ({paper['author']}): INVALID"

        # Verify review signatures
        review_status = []
        for review in paper.get('reviews', []):
            h_review = SHA256.new(json.dumps(review['review_data']).encode())
            sig_review = base64.b64decode(review['signature'])

            try:
                reviewer_key = self.user_keys[review['reviewer']]['public']
                pkcs1_15.new(reviewer_key).verify(h_review, sig_review)
                review_status.append(f"✅ {review['reviewer']}: Score {review['score']} - VALID")
            except:
                review_status.append(f"❌ {review['reviewer']}: Score {review['score']} - INVALID")

        return {
            'paper': paper_id,
            'author_status': author_status,
            'review_status': review_status
        }

    # ========== MODULE 5: ACCESS CONTROL & VIEWING ==========
    def view_paper(self, paper_id, decrypt=False):
        """View paper (optionally decrypted for authorized users)"""
        paper = None
        for p in self.research_papers:
            if p['id'] == paper_id:
                paper = p
                break

        if not paper:
            return "Paper not found"

        role = self.users[self.current_user]['role']
        dept = self.users[self.current_user]['department']

        view_data = {
            'id': paper['id'],
            'title': paper['title'],
            'abstract': paper['abstract'],
            'author': paper['author'],
            'department': paper['department'],
            'status': paper['status'],
            'submission_date': paper['submission_date'][:10],
            'keywords': paper['keywords'],
            'reviews': len(paper['reviews'])
        }

        # Check permissions for decryption
        can_decrypt = False
        if role == 'admin':
            can_decrypt = True
        elif role == 'professor' and dept == paper['department']:
            can_decrypt = True
        elif self.current_user == paper['author']:
            can_decrypt = True

        if decrypt and can_decrypt:
            # In real system, decrypt using paper_key
            view_data['content'] = '[DECRYPTED CONTENT WOULD APPEAR HERE]'
            view_data['decryption_status'] = 'Authorized - Content would be decrypted'
        else:
            view_data['content'] = '[ENCRYPTED - REQUIRES AUTHORIZATION]'
            view_data['decryption_status'] = 'Not authorized for decryption'

        self.log_audit(f'VIEW_PAPER: {paper_id}')
        return view_data

    def get_statistics(self):
        """Get portal statistics (admin only)"""
        if self.users[self.current_user]['role'] != 'admin':
            return "Admin only"

        stats = {
            'total_papers': len(self.research_papers),
            'total_data_sets': len(self.research_data),
            'by_department': {},
            'by_status': {},
            'search_index_size': len(self.encrypted_index)
        }

        for paper in self.research_papers:
            dept = paper['department']
            status = paper['status']

            stats['by_department'][dept] = stats['by_department'].get(dept, 0) + 1
            stats['by_status'][status] = stats['by_status'].get(status, 0) + 1

        return stats


def main():
    portal = UniversityResearchPortal()

    print("🎓 UNIVERSITY RESEARCH PORTAL")
    print("=" * 60)
    print("Advanced Cryptography: SSE + Homomorphic + RSA + AES")
    print("\nRoles: student, researcher, professor, admin")
    print("Users: student1, student2, researcher1, researcher2, professor1, professor2, admin")
    print("Passwords: stu123, stu456, res123, res456, prof123, prof456, admin123")

    # Login
    while True:
        print("\n" + "=" * 40)
        user = input("Username: ")
        pwd = input("Password: ")

        if portal.login(user, pwd):
            role = portal.users[user]['role']
            dept = portal.users[user].get('department', 'N/A')
            print(f"\n✅ Welcome, {user} ({role}, {dept})!")
            break
        else:
            print("❌ Invalid credentials")

    # Main menu
    while True:
        user_info = portal.users[portal.current_user]
        role = user_info['role']
        dept = user_info.get('department', '')

        print(f"\n🔬 {portal.current_user.upper()} - {role.upper()}")
        if dept:
            print(f"Department: {dept}")
        print("-" * 40)

        # Common options
        common_menu = [
            "1. Search Research Papers (SSE)",
            "2. View Paper Details",
            "3. Verify Paper Signatures",
            "4. View Portal Statistics"
        ]

        # Role-specific options
        if role in ['researcher', 'professor']:
            print("\n📝 RESEARCH FUNCTIONS:")
            print("5. Submit Research Paper (AES + RSA)")
            print("6. Submit Research Data (Homomorphic)")
            print("7. Review Paper (Professors only)")

        if role == 'professor':
            print("8. Collaborative Analysis")

        if role == 'admin':
            print("\n🛡️ ADMIN FUNCTIONS:")
            print("5. System Audit")
            print("6. Security Report")
            print("7. Manage Users")

        print("\n0. Logout")

        # Display menu
        for item in common_menu:
            print(item)

        if role in ['researcher', 'professor']:
            print("5. Submit Research Paper (AES + RSA)")
            print("6. Submit Research Data (Homomorphic)")
            if role == 'professor':
                print("7. Review Paper")
                print("8. Collaborative Analysis")

        if role == 'admin':
            print("5. System Audit")
            print("6. Security Report")
            print("7. Manage Users")

        choice = input("\nSelect: ")

        if choice == '0':
            print("👋 Logging out...")
            break

        # Common functions
        if choice == '1':
            query = input("Search papers by keyword: ")
            results = portal.search_papers(query)

            if results:
                print(f"\n🔍 SEARCH RESULTS ({len(results)} papers):")
                for paper in results:
                    print(f"\n{paper['id']}: {paper['title']}")
                    print(f"Author: {paper['author']}, Dept: {paper['department']}")
                    print(f"Abstract: {paper['abstract'][:100]}...")
                    print(f"Keywords: {', '.join(paper['keywords'])}")
            else:
                print("No papers found")

        elif choice == '2':
            paper_id = input("Paper ID: ")
            decrypt = input("Attempt decryption? (y/n): ").lower() == 'y'
            result = portal.view_paper(paper_id, decrypt)

            if isinstance(result, dict):
                print(f"\n📄 PAPER DETAILS:")
                print(f"ID: {result['id']}")
                print(f"Title: {result['title']}")
                print(f"Author: {result['author']}")
                print(f"Department: {result['department']}")
                print(f"Status: {result['status']}")
                print(f"Abstract: {result['abstract'][:200]}...")
                print(f"Keywords: {', '.join(result['keywords'])}")
                print(f"Reviews: {result['reviews']}")
                print(f"\nContent: {result['content']}")
                print(f"Decryption: {result['decryption_status']}")
            else:
                print(result)

        elif choice == '3':
            paper_id = input("Paper ID to verify: ")
            result = portal.verify_paper_signature(paper_id)

            if isinstance(result, dict):
                print(f"\n🔐 SIGNATURE VERIFICATION for {result['paper']}:")
                print(f"\nAuthor Signature:")
                print(f"  {result['author_status']}")

                if result['review_status']:
                    print(f"\nReview Signatures:")
                    for status in result['review_status']:
                        print(f"  {status}")
                else:
                    print("\nNo reviews yet")
            else:
                print(result)

        elif choice == '4':
            if role == 'admin':
                stats = portal.get_statistics()
                print(f"\n📊 PORTAL STATISTICS:")
                print(f"Total Papers: {stats['total_papers']}")
                print(f"Total Datasets: {stats['total_data_sets']}")
                print(f"Search Index Size: {stats['search_index_size']}")
                print(f"\nPapers by Department:")
                for dept, count in stats['by_department'].items():
                    print(f"  {dept}: {count}")
                print(f"\nPapers by Status:")
                for status, count in stats['by_status'].items():
                    print(f"  {status}: {count}")
            else:
                # Basic stats for non-admins
                print(f"\n📊 BASIC STATISTICS:")
                print(f"Total Papers: {len(portal.research_papers)}")
                dept_papers = len([p for p in portal.research_papers
                                   if p['department'] == dept])
                print(f"Papers in {dept}: {dept_papers}")

        # Researcher/Professor functions
        elif choice == '5' and role in ['researcher', 'professor']:
            print("\n📝 SUBMIT RESEARCH PAPER")
            title = input("Paper Title: ")
            abstract = input("Abstract: ")
            content = input("Content: ")
            keywords = input("Keywords (comma-separated): ")

            result = portal.submit_research_paper(title, abstract, content, keywords)
            print(f"\n{result}")

        elif choice == '6' and role in ['researcher', 'professor']:
            print("\n🔢 SUBMIT RESEARCH DATA (Homomorphic)")
            print("Enter numerical data points (comma-separated):")
            data_input = input("Data: ")

            try:
                data_points = [float(x.strip()) for x in data_input.split(',')]
                analysis_type = input("Analysis type (sum/avg): ")

                result = portal.submit_research_data(data_points, analysis_type)
                print(f"\n{result}")
            except:
                print("❌ Invalid data format")

        elif choice == '7' and role == 'professor':
            print("\n📋 REVIEW PAPER")
            paper_id = input("Paper ID: ")
            try:
                score = int(input("Review Score (1-10): "))
                comments = input("Comments: ")

                result = portal.review_paper(paper_id, score, comments)
                print(f"\n{result}")
            except:
                print("❌ Invalid score")

        elif choice == '8' and role == 'professor':
            print("\n🤝 COLLABORATIVE ANALYSIS")
            print("Enter data set IDs to combine (comma-separated):")
            data_ids = [id.strip() for id in input("Data IDs: ").split(',')]

            result = portal.collaborative_analysis(data_ids)
            print(f"\n{result}")

        # Admin functions
        elif choice == '5' and role == 'admin':
            print("\n📋 SYSTEM AUDIT")
            print(f"Total audit entries: {len(portal.audit_log)}")
            print("\nRecent activity:")
            for entry in portal.audit_log[-10:]:
                time = entry['timestamp'][11:19]
                print(f"  {time} - {entry['user']}: {entry['action']}")

        elif choice == '6' and role == 'admin':
            print("\n🛡️ SECURITY REPORT")
            print("✅ RSA Digital Signatures: Active")
            print("✅ AES Document Encryption: Active")
            print("✅ Searchable Encryption (SSE): Active")
            print("✅ Homomorphic Encryption: Active (Demo)")
            print("✅ SHA-256 Hashing: Active")
            print(f"✅ User Keys: {len(portal.user_keys)} generated")
            print(f"✅ Papers Encrypted: {len(portal.research_papers)}")

        elif choice == '7' and role == 'admin':
            print("\n👥 USER MANAGEMENT")
            for user, info in portal.users.items():
                dept = info.get('department', 'N/A')
                print(f"  {user}: {info['role']} - {dept}")


if __name__ == "__main__":
    main()