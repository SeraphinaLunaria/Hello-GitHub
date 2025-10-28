#!/usr/bin/env python3
"""
File Integrity Checker
Monitor files for unauthorized changes using cryptographic hashes
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple


class FileIntegrityChecker:
    """Monitor file integrity using hash comparisons"""

    def __init__(self, database_file: str = "integrity_db.json"):
        self.database_file = database_file
        self.database: Dict = {}
        self.load_database()

    def calculate_hash(self, filepath: str) -> str:
        """
        Calculate SHA-256 hash of a file

        Args:
            filepath: Path to the file

        Returns:
            str: Hexadecimal hash string
        """
        sha256_hash = hashlib.sha256()

        try:
            with open(filepath, "rb") as f:
                # Read in chunks for large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)

            return sha256_hash.hexdigest()

        except Exception as e:
            print(f"Error calculating hash for {filepath}: {e}")
            return ""

    def add_file(self, filepath: str) -> bool:
        """
        Add a file to the monitoring database

        Args:
            filepath: Path to the file

        Returns:
            bool: True if added successfully
        """
        if not os.path.exists(filepath):
            print(f"✗ File not found: {filepath}")
            return False

        if not os.path.isfile(filepath):
            print(f"✗ Not a file: {filepath}")
            return False

        try:
            file_hash = self.calculate_hash(filepath)
            file_stat = os.stat(filepath)

            self.database[filepath] = {
                'hash': file_hash,
                'size': file_stat.st_size,
                'modified': file_stat.st_mtime,
                'added': datetime.now().isoformat(),
                'last_checked': datetime.now().isoformat(),
                'status': 'clean'
            }

            print(f"✓ Added {filepath} to monitoring")
            return True

        except Exception as e:
            print(f"✗ Error adding file: {e}")
            return False

    def add_directory(self, directory: str, recursive: bool = True) -> int:
        """
        Add all files in a directory to monitoring

        Args:
            directory: Path to directory
            recursive: Include subdirectories

        Returns:
            int: Number of files added
        """
        if not os.path.exists(directory):
            print(f"✗ Directory not found: {directory}")
            return 0

        count = 0
        path = Path(directory)

        try:
            if recursive:
                files = path.rglob('*')
            else:
                files = path.glob('*')

            for file in files:
                if file.is_file():
                    if self.add_file(str(file)):
                        count += 1

            print(f"\n✓ Added {count} files from {directory}")
            return count

        except Exception as e:
            print(f"✗ Error scanning directory: {e}")
            return count

    def check_file(self, filepath: str) -> Tuple[str, str]:
        """
        Check if a file has been modified

        Args:
            filepath: Path to the file

        Returns:
            Tuple[str, str]: Status and message
        """
        if filepath not in self.database:
            return "unknown", "File not in database"

        if not os.path.exists(filepath):
            return "missing", "File has been deleted"

        try:
            current_hash = self.calculate_hash(filepath)
            stored_hash = self.database[filepath]['hash']

            # Update last checked time
            self.database[filepath]['last_checked'] = datetime.now().isoformat()

            if current_hash != stored_hash:
                self.database[filepath]['status'] = 'modified'
                return "modified", "File has been modified"

            file_stat = os.stat(filepath)
            stored_size = self.database[filepath]['size']

            if file_stat.st_size != stored_size:
                self.database[filepath]['status'] = 'modified'
                return "modified", "File size changed"

            self.database[filepath]['status'] = 'clean'
            return "clean", "File is unchanged"

        except Exception as e:
            return "error", f"Error checking file: {e}"

    def check_all(self) -> Dict[str, List[str]]:
        """
        Check all monitored files

        Returns:
            Dict: Files categorized by status
        """
        results = {
            'clean': [],
            'modified': [],
            'missing': [],
            'error': []
        }

        print("\nChecking all monitored files...")

        for filepath in self.database.keys():
            status, message = self.check_file(filepath)
            results[status].append(filepath)

        return results

    def generate_report(self, results: Dict[str, List[str]]):
        """Generate and display integrity check report"""
        print("\n" + "="*70)
        print("FILE INTEGRITY CHECK REPORT")
        print("="*70)
        print(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Files Monitored: {len(self.database)}")

        print("\n--- Summary ---")
        print(f"  Clean:    {len(results['clean'])}")
        print(f"  Modified: {len(results['modified'])}")
        print(f"  Missing:  {len(results['missing'])}")
        print(f"  Errors:   {len(results['error'])}")

        if results['modified']:
            print("\n--- MODIFIED FILES (Alert!) ---")
            for filepath in results['modified']:
                info = self.database[filepath]
                added = info.get('added', 'Unknown')[:10]
                print(f"  ⚠️ {filepath}")
                print(f"     Added to monitoring: {added}")

        if results['missing']:
            print("\n--- MISSING FILES (Alert!) ---")
            for filepath in results['missing']:
                print(f"  ⚠️ {filepath}")

        if results['error']:
            print("\n--- ERRORS ---")
            for filepath in results['error']:
                print(f"  ✗ {filepath}")

        if not results['modified'] and not results['missing']:
            print("\n✓ All files are intact - No unauthorized changes detected")

        print("\n" + "="*70)

    def update_baseline(self, filepath: str) -> bool:
        """
        Update the baseline hash for a file (after authorized change)

        Args:
            filepath: Path to the file

        Returns:
            bool: True if updated successfully
        """
        if filepath not in self.database:
            print(f"✗ File not in database: {filepath}")
            return False

        if not os.path.exists(filepath):
            print(f"✗ File not found: {filepath}")
            return False

        try:
            file_hash = self.calculate_hash(filepath)
            file_stat = os.stat(filepath)

            self.database[filepath].update({
                'hash': file_hash,
                'size': file_stat.st_size,
                'modified': file_stat.st_mtime,
                'last_checked': datetime.now().isoformat(),
                'status': 'clean'
            })

            print(f"✓ Updated baseline for {filepath}")
            return True

        except Exception as e:
            print(f"✗ Error updating baseline: {e}")
            return False

    def remove_file(self, filepath: str) -> bool:
        """Remove a file from monitoring"""
        if filepath in self.database:
            del self.database[filepath]
            print(f"✓ Removed {filepath} from monitoring")
            return True
        else:
            print(f"✗ File not in database: {filepath}")
            return False

    def list_files(self):
        """List all monitored files"""
        print("\n" + "="*70)
        print("MONITORED FILES")
        print("="*70)

        if not self.database:
            print("\nNo files are being monitored")
            return

        print(f"\nTotal: {len(self.database)} files\n")

        for filepath, info in sorted(self.database.items()):
            status = info.get('status', 'unknown')
            added = info.get('added', 'Unknown')[:10]
            size = info.get('size', 0)

            status_symbol = {
                'clean': '✓',
                'modified': '⚠️',
                'unknown': '?'
            }.get(status, '?')

            print(f"{status_symbol} {filepath}")
            print(f"   Status: {status}, Size: {size} bytes, Added: {added}")

        print("\n" + "="*70)

    def save_database(self):
        """Save database to file"""
        try:
            with open(self.database_file, 'w') as f:
                json.dump(self.database, f, indent=2)
            print(f"✓ Database saved to {self.database_file}")
        except Exception as e:
            print(f"✗ Error saving database: {e}")

    def load_database(self):
        """Load database from file"""
        if not os.path.exists(self.database_file):
            print(f"No existing database found. Starting fresh.")
            return

        try:
            with open(self.database_file, 'r') as f:
                self.database = json.load(f)
            print(f"✓ Loaded database from {self.database_file}")
            print(f"  Monitoring {len(self.database)} files")
        except Exception as e:
            print(f"✗ Error loading database: {e}")
            self.database = {}


def main():
    """Main function"""
    checker = FileIntegrityChecker()

    print("\n" + "="*70)
    print("FILE INTEGRITY CHECKER")
    print("="*70)

    while True:
        print("\nOptions:")
        print("  1. Add file")
        print("  2. Add directory")
        print("  3. Check all files")
        print("  4. Check specific file")
        print("  5. Update baseline")
        print("  6. Remove file")
        print("  7. List monitored files")
        print("  8. Save database")
        print("  9. Quit")

        choice = input("\nSelect option: ").strip()

        if choice == '1':
            filepath = input("Enter file path: ").strip()
            checker.add_file(filepath)

        elif choice == '2':
            directory = input("Enter directory path: ").strip()
            recursive = input("Include subdirectories? (y/n): ").strip().lower() == 'y'
            checker.add_directory(directory, recursive)

        elif choice == '3':
            results = checker.check_all()
            checker.generate_report(results)

        elif choice == '4':
            filepath = input("Enter file path: ").strip()
            status, message = checker.check_file(filepath)
            print(f"\nStatus: {status}")
            print(f"Message: {message}")

        elif choice == '5':
            filepath = input("Enter file path: ").strip()
            confirm = input(f"Update baseline for {filepath}? (y/n): ").strip().lower()
            if confirm == 'y':
                checker.update_baseline(filepath)

        elif choice == '6':
            filepath = input("Enter file path: ").strip()
            checker.remove_file(filepath)

        elif choice == '7':
            checker.list_files()

        elif choice == '8':
            checker.save_database()

        elif choice == '9':
            print("Save database before quitting? (y/n): ", end='')
            if input().strip().lower() == 'y':
                checker.save_database()
            print("\nGoodbye!")
            break

        else:
            print("Invalid option")


if __name__ == "__main__":
    main()
