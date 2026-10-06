import os
import time
import random
import shutil

class RansomwareSimulator:
    def __init__(self, test_dir="~/Documents/RansomwareTest"):
        self.test_dir = os.path.expanduser(test_dir)
        self.infected_files = []
    
    def create_test_environment(self, num_files=50):
        print(f"[1] Creating test environment at {self.test_dir}")
        
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        
        os.makedirs(self.test_dir, exist_ok=True)
        
        subdirs = ["Documents", "Photos", "Videos", "Data"]
        for subdir in subdirs:
            os.makedirs(os.path.join(self.test_dir, subdir), exist_ok=True)
        
        file_types = [
            (".txt", "This is a normal text document.\n" * 50),
            (".docx", "Important business document content.\n" * 30),
            (".pdf", "PDF document with regular content.\n" * 40),
            (".jpg", "Photo metadata and image data.\n" * 20),
            (".xlsx", "Spreadsheet with financial data.\n" * 25)
        ]
        
        files_created = 0
        for i in range(num_files):
            subdir = random.choice(subdirs)
            ext, content = random.choice(file_types)
            filename = f"file_{i}{ext}"
            filepath = os.path.join(self.test_dir, subdir, filename)
            
            with open(filepath, 'w') as f:
                f.write(content)
            
            files_created += 1
        
        print(f"[✓] Created {files_created} normal files")
        print(f"[✓] Test environment ready at: {self.test_dir}")
        print()
    
    def simulate_ransomware_attack(self, infection_rate=0.8, speed="fast"):
        print("[2] Simulating ransomware attack...")
        print("[!] WARNING: This will modify files in the test directory")
        
        all_files = []
        for root, dirs, files in os.walk(self.test_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                all_files.append(filepath)
        
        num_to_encrypt = int(len(all_files) * infection_rate)
        files_to_encrypt = random.sample(all_files, num_to_encrypt)
        
        print(f"[!] Targeting {num_to_encrypt} files out of {len(all_files)}")
        
        delays = {"instant": 0, "fast": 0.1, "medium": 0.5, "slow": 1.0}
        delay = delays.get(speed, 0.1)
        
        print(f"[!] Beginning encryption in 3 seconds...")
        time.sleep(3)
        
        start_time = time.time()
        
        for i, filepath in enumerate(files_to_encrypt):
            try:
                with open(filepath, 'wb') as f:
                    random_data = os.urandom(random.randint(1000, 5000))
                    f.write(random_data)
                
                new_filepath = filepath + ".encrypted"
                os.rename(filepath, new_filepath)
                
                self.infected_files.append(new_filepath)
                
                if (i + 1) % 10 == 0:
                    print(f"[!] Encrypted {i + 1}/{num_to_encrypt} files...")
                
                time.sleep(delay)
            
            except Exception as e:
                print(f"[!] Error with {filepath}: {e}")
        
        elapsed = time.time() - start_time
        
        print(f"\n[✓] Attack simulation complete!")
        print(f"[✓] Encrypted {len(self.infected_files)} files in {elapsed:.2f} seconds")
        print(f"[✓] Average: {len(self.infected_files)/elapsed:.1f} files/second")
        
        self.create_ransom_note()
    
    def create_ransom_note(self):
        note_path = os.path.join(self.test_dir, "README_DECRYPT.txt")
        
        note_content = """
YOUR FILES HAVE BEEN ENCRYPTED

This is a SIMULATION for testing RansomwareAudit detection.
No real encryption occurred - files were filled with random data.
"""
        
        with open(note_path, 'w') as f:
            f.write(note_content)
        
        print(f"[!] Ransom note created: {note_path}")
    
    def show_infection_status(self):
        print("\n" + "="*60)
        print("INFECTION STATISTICS")
        print("="*60)
        
        total_files = 0
        encrypted_files = 0
        
        for root, dirs, files in os.walk(self.test_dir):
            for filename in files:
                total_files += 1
                if filename.endswith('.encrypted'):
                    encrypted_files += 1
        
        print(f"Total files: {total_files}")
        print(f"Encrypted files: {encrypted_files}")
        print(f"Infection rate: {encrypted_files/total_files*100:.1f}%")
        print(f"Test directory: {self.test_dir}")
        print("="*60 + "\n")
    
    def cleanup(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
            print(f"[✓] Cleaned up test directory: {self.test_dir}")


def run_full_simulation():
    print("="*60)
    print("    RANSOMWARE AUDIT - ATTACK SIMULATOR")
    print("="*60)
    print()
    
    sim = RansomwareSimulator()
    sim.create_test_environment(num_files=50)
    
    print("[INFO] Normal files created.")
    print()
    
    input("Press ENTER to simulate ransomware attack...")
    print()
    
    sim.simulate_ransomware_attack(infection_rate=0.8, speed="fast")
    sim.show_infection_status()
    
    print("\n" + "="*60)
    print("NOW TEST YOUR RANSOMWAREAUDIT SYSTEM")
    print("="*60)
    print()
    print("Scan the infected directory:")
    print(f"  python3 -m RansomwareAudit.run ~/Documents/RansomwareTest --html --quarantine --threshold 10")
    print()
    print("="*60)
    print()
    
    choice = input("Clean up test directory? (y/n): ")
    if choice.lower() == 'y':
        sim.cleanup()
    else:
        print(f"[INFO] Test directory preserved at: {sim.test_dir}")


if __name__ == "__main__":
    run_full_simulation()
