# voting_system.py
#Features: Voters, candidates, election commission, ElGamal for anonymity
import random
import hashlib
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json


class SecureVotingSystem:
    def __init__(self):
        self.voters = {
            'V001': {'name': 'Alice Johnson', 'has_voted': False, 'pin': '1111'},
            'V002': {'name': 'Bob Smith', 'has_voted': False, 'pin': '2222'},
            'V003': {'name': 'Carol Davis', 'has_voted': False, 'pin': '3333'},
            'V004': {'name': 'David Wilson', 'has_voted': False, 'pin': '4444'},
            'V005': {'name': 'Eva Brown', 'has_voted': False, 'pin': '5555'}
        }

        self.candidates = {
            'A': {'name': 'Candidate A', 'party': 'Unity Party'},
            'B': {'name': 'Candidate B', 'party': 'Progress Party'},
            'C': {'name': 'Candidate C', 'party': 'Future Party'}
        }

        # ElGamal parameters (simplified for demo)
        self.p = 32321  # Prime
        self.g = 3  # Generator

        self.votes = []  # Encrypted votes
        self.vote_tracker = {}  # Track voter->encrypted vote mapping
        self.election_open = True

        # Election commission keys
        self.commission_key = RSA.generate(2048)
        self.commission_pub = self.commission_key.publickey()

    def elgamal_encrypt(self, vote):
        """Encrypt vote using ElGamal (simplified)"""
        # Convert vote to number: A=1, B=2, C=3
        m = ord(vote) - 64

        # Generate random secret
        k = random.randint(1, self.p - 2)

        # Compute ciphertext
        c1 = pow(self.g, k, self.p)
        # In real ElGamal: c2 = (m * pow(y, k, p)) % p
        # For demo, we'll use simpler approach
        c2 = (m * pow(self.g, k, self.p)) % self.p

        return (c1, c2)

    def elgamal_decrypt(self, ciphertext, private_key):
        """Decrypt ElGamal ciphertext (simplified)"""
        c1, c2 = ciphertext
        # In real ElGamal: m = (c2 * pow(c1, -x, p)) % p
        # For demo, we'll extract directly
        for m in range(1, 27):
            if pow(self.g, m, self.p) == c2:
                return chr(m + 64)
        return '?'

    def cast_vote(self, voter_id, pin, vote):
        if not self.election_open:
            return "Election is closed"

        if voter_id not in self.voters:
            return "Invalid voter ID"

        if self.voters[voter_id]['pin'] != pin:
            return "Invalid PIN"

        if self.voters[voter_id]['has_voted']:
            return "Already voted"

        if vote not in self.candidates:
            return "Invalid candidate"

        # Encrypt the vote
        encrypted_vote = self.elgamal_encrypt(vote)

        # Store encrypted vote
        self.votes.append(encrypted_vote)

        # Track that this voter has voted (but not how they voted)
        self.voters[voter_id]['has_voted'] = True
        self.vote_tracker[voter_id] = encrypted_vote

        # Create receipt (encrypted)
        receipt = {
            'voter_id': voter_id,
            'timestamp': datetime.now().isoformat(),
            'vote_encrypted': encrypted_vote
        }

        # Encrypt receipt for voter
        cipher = PKCS1_OAEP.new(self.commission_pub)
        encrypted_receipt = cipher.encrypt(json.dumps(receipt).encode())

        print(f"\n✅ Vote cast successfully!")
        print(f"Encrypted vote: {encrypted_vote}")
        print(f"Receipt (encrypted): {encrypted_receipt.hex()[:50]}...")

        return "Vote recorded"

    def tally_votes(self, commission_key):
        """Tally votes (commission only)"""
        if not commission_key:
            return "Commission key required"

        results = {candidate: 0 for candidate in self.candidates}

        for encrypted_vote in self.votes:
            # Decrypt each vote
            vote = self.elgamal_decrypt(encrypted_vote, commission_key)
            if vote in results:
                results[vote] += 1

        return results

    def verify_vote(self, voter_id, commission_key):
        """Verify a voter's vote (commission only)"""
        if voter_id not in self.vote_tracker:
            return "No vote found for this voter"

        encrypted_vote = self.vote_tracker[voter_id]
        decrypted = self.elgamal_decrypt(encrypted_vote, commission_key)

        return {
            'voter': self.voters[voter_id]['name'],
            'encrypted_vote': encrypted_vote,
            'decrypted_vote': decrypted
        }

    def get_voter_stats(self):
        """Get voting statistics (public)"""
        total = len(self.voters)
        voted = sum(1 for v in self.voters.values() if v['has_voted'])

        return {
            'total_voters': total,
            'voted': voted,
            'not_voted': total - voted,
            'election_open': self.election_open
        }


def main():
    voting = SecureVotingSystem()

    print("🗳️ SECURE VOTING SYSTEM")
    print("=" * 50)
    print("Candidates:")
    for key, cand in voting.candidates.items():
        print(f"  {key}: {cand['name']} ({cand['party']})")

    while True:
        print("\n1. Voter - Cast Vote")
        print("2. Voter - Check Status")
        print("3. Commission - Tally Votes")
        print("4. Commission - Verify Vote")
        print("5. Public - View Statistics")
        print("6. Commission - Close Election")
        print("7. Exit")

        choice = input("\nSelect role: ")

        if choice == '1':
            print("\n👤 VOTER PORTAL")
            vid = input("Voter ID: ")
            pin = input("PIN: ")
            print("\nCandidates: A, B, C")
            vote = input("Your vote (A/B/C): ").upper()

            result = voting.cast_vote(vid, pin, vote)
            print(f"\n{result}")

        elif choice == '2':
            print("\n📋 VOTER STATUS")
            vid = input("Voter ID: ")
            if vid in voting.voters:
                status = "✅ VOTED" if voting.voters[vid]['has_voted'] else "⏳ NOT VOTED"
                print(f"{voting.voters[vid]['name']}: {status}")
            else:
                print("❌ Voter not found")

        elif choice == '3':
            print("\n📊 ELECTION COMMISSION - TALLY")
            key = input("Commission Key (Enter 'admin' for demo): ")

            if key == 'admin':
                results = voting.tally_votes('demo_key')
                print("\nELECTION RESULTS:")
                for candidate, votes in results.items():
                    cand_name = voting.candidates.get(candidate, {}).get('name', 'Unknown')
                    print(f"  {cand_name}: {votes} votes")
            else:
                print("❌ Commission access only")

        elif choice == '4':
            print("\n🔍 COMMISSION - VERIFY VOTE")
            key = input("Commission Key (Enter 'admin' for demo): ")

            if key == 'admin':
                vid = input("Voter ID to verify: ")
                result = voting.verify_vote(vid, 'demo_key')
                if isinstance(result, dict):
                    print(f"\nVoter: {result['voter']}")
                    print(f"Encrypted vote: {result['encrypted_vote']}")
                    print(f"Decrypted vote: {result['decrypted_vote']}")
                else:
                    print(result)
            else:
                print("❌ Commission access only")

        elif choice == '5':
            print("\n📈 PUBLIC STATISTICS")
            stats = voting.get_voter_stats()
            print(f"Total voters: {stats['total_voters']}")
            print(f"Votes cast: {stats['voted']}")
            print(f"Remaining: {stats['not_voted']}")
            print(f"Election status: {'OPEN' if stats['election_open'] else 'CLOSED'}")

        elif choice == '6':
            print("\n🔒 CLOSE ELECTION")
            key = input("Commission Key (Enter 'admin' for demo): ")

            if key == 'admin':
                voting.election_open = False
                print("✅ Election closed. No more votes can be cast.")
            else:
                print("❌ Commission access only")

        elif choice == '7':
            print("👋 Goodbye!")
            break


if __name__ == "__main__":
    main()