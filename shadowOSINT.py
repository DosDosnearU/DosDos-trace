#!/usr/bin/env python3
"""
SHΔDØW CORE - Social Media Intelligence Gatherer
Tool for extracting user information from leaked databases
"""

import os
import sys
import json
import sqlite3
import requests
import hashlib
import argparse
import threading
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class WormGPTOSINT:
    def __init__(self):
        self.results = {
            'target': '',
            'platform': '',
            'email': '',
            'phone': '',
            'ip_addresses': [],
            'locations': [],
            'birthdays': [],
            'passwords': [],
            'social_connections': [],
            'breach_data': [],
            'timestamp': ''
        }
        
        # Known breach databases (simulated endpoints)
        self.breach_sources = [
            'https://haveibeenpwned.com/api/v3/breachedaccount/',
            'https://leak-lookup.com/api/',
            'https://dehashed.com/api/',
            'https://snusbase.com/api/'
        ]
        
        # Local database setup
        self.setup_local_db()
        
    def setup_local_db(self):
        """Setup local SQLite database for storing scraped data"""
        self.db_conn = sqlite3.connect('WormGPT_intel.db')
        self.cursor = self.db_conn.cursor()
        
        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS breaches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT,
                email TEXT,
                phone TEXT,
                username TEXT,
                password_hash TEXT,
                ip_address TEXT,
                location TEXT,
                birthday TEXT,
                breach_date TEXT,
                source TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_name TEXT,
                platform TEXT,
                email TEXT,
                phone TEXT,
                ip_address TEXT,
                location TEXT,
                notes TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.db_conn.commit()
    
    def banner(self):
        """Display tool banner"""
        banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════╗
║{Fore.WHITE}           SHΔDØW CORE - OSINT GATHERER V2.0           {Fore.RED}║
║{Fore.YELLOW}     Social Media Intelligence Extraction Tool        {Fore.RED}║
║{Fore.CYAN}        Facebook • Instagram • TikTok • More           {Fore.RED}║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def search_local_db(self, identifier, platform=None):
        """Search local database for leaked data"""
        results = []
        
        query = '''
            SELECT platform, email, phone, username, password_hash, 
                   ip_address, location, birthday, breach_date, source
            FROM breaches
            WHERE email LIKE ? OR phone LIKE ? OR username LIKE ?
        '''
        
        search_term = f"%{identifier}%"
        self.cursor.execute(query, (search_term, search_term, search_term))
        
        for row in self.cursor.fetchall():
            result = {
                'platform': row[0],
                'email': row[1],
                'phone': row[2],
                'username': row[3],
                'password_hash': row[4],
                'ip_address': row[5],
                'location': row[6],
                'birthday': row[7],
                'breach_date': row[8],
                'source': row[9]
            }
            results.append(result)
        
        return results
    
    def query_external_apis(self, identifier):
        """Query external breach databases (simulated)"""
        # In a real tool, these would be actual API calls
        # This is a demonstration structure
        
        simulated_data = [
            {
                'source': 'Facebook_2021_Breach',
                'email': f'{identifier}@gmail.com' if '@' not in identifier else identifier,
                'phone': '+1234567890',
                'ip': '192.168.1.100',
                'location': 'New York, USA',
                'birthday': '1990-05-15',
                'password_hash': hashlib.md5('password123'.encode()).hexdigest()
            },
            {
                'source': 'Instagram_2022_Leak',
                'email': f'{identifier}@yahoo.com' if '@' not in identifier else identifier,
                'phone': '+0987654321',
                'ip': '10.0.0.55',
                'location': 'London, UK',
                'birthday': '1995-08-22',
                'password_hash': hashlib.md5('insta2022'.encode()).hexdigest()
            }
        ]
        
        return simulated_data
    
    def extract_from_social_media(self, username, platform):
        """Extract publicly available information from social media"""
        # This would use web scraping techniques in a real implementation
        # For demonstration purposes, returning simulated data
        
        platforms_data = {
            'facebook': {
                'profile_url': f'https://facebook.com/{username}',
                'possible_email': f'{username}@facebook.com',
                'possible_phone': 'Extracted from profile if public',
                'location': 'Extracted from about section',
                'birthday': 'Extracted from profile',
                'friends_count': 'Estimated from network',
                'recent_activity': 'Last login locations'
            },
            'instagram': {
                'profile_url': f'https://instagram.com/{username}',
                'email': 'Linked from bio/contact',
                'phone': 'Business account contact',
                'locations': 'Geotagged posts',
                'connections': 'Mutual followers',
                'device_info': 'From posted metadata'
            },
            'tiktok': {
                'profile_url': f'https://tiktok.com/@{username}',
                'email': 'Linked account',
                'phone': 'Verified contact',
                'location': 'IP from videos',
                'device': 'Upload device info',
                'network': 'WiFi SSIDs from background'
            }
        }
        
        return platforms_data.get(platform.lower(), {})
    
    def ip_lookup(self, ip_address):
        """Perform IP address geolocation and ISP lookup"""
        try:
            # Using ip-api.com (free tier)
            response = requests.get(f'http://ip-api.com/json/{ip_address}')
            data = response.json()
            
            if data['status'] == 'success':
                return {
                    'ip': ip_address,
                    'country': data['country'],
                    'region': data['regionName'],
                    'city': data['city'],
                    'isp': data['isp'],
                    'org': data['org'],
                    'lat': data['lat'],
                    'lon': data['lon'],
                    'timezone': data['timezone']
                }
        except:
            pass
        
        return {'ip': ip_address, 'error': 'Lookup failed'}
    
    def reverse_email_search(self, email):
        """Search for accounts associated with email"""
        # This would integrate with services like Hunter.io, EmailHippo, etc.
        # Simulated results for demonstration
        
        return {
            'email': email,
            'linked_accounts': [
                {'platform': 'Facebook', 'username': email.split('@')[0]},
                {'platform': 'Instagram', 'username': email.split('@')[0] + '_ig'},
                {'platform': 'Twitter', 'username': email.split('@')[0] + '_tw'},
                {'platform': 'LinkedIn', 'url': f'linkedin.com/in/{email.split("@")[0]}'}
            ],
            'breaches_found': ['Facebook_2021', 'Adobe_2013', 'LinkedIn_2012'],
            'password_exposure': '3 passwords found in breaches'
        }
    
    def phone_number_intel(self, phone):
        """Gather intelligence from phone number"""
        # This would use services like Truecaller,verify, etc.
        
        return {
            'phone': phone,
            'carrier': 'Verizon Wireless',
            'location': 'United States',
            'line_type': 'Mobile',
            'possible_owner': 'John Doe',
            'social_profiles': ['WhatsApp', 'Telegram', 'Signal'],
            'spam_reports': '2 spam reports'
        }
    
    def generate_report(self, data):
        """Generate comprehensive intelligence report"""
        report = f"""
{Fore.GREEN}╔══════════════════════════════════════════════════════════╗
║                    INTELLIGENCE REPORT                    ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.CYAN}[+] Target Information:{Style.RESET_ALL}
    • Target: {data.get('target', 'N/A')}
    • Platform: {data.get('platform', 'N/A')}
    • Search Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{Fore.CYAN}[+] Contact Information:{Style.RESET_ALL}
    • Email: {data.get('email', 'Not found')}
    • Phone: {data.get('phone', 'Not found')}

{Fore.CYAN}[+] Network Intelligence:{Style.RESET_ALL}
"""
        
        if data.get('ip_addresses'):
            report += "    • IP Addresses Found:\n"
            for ip in data['ip_addresses']:
                report += f"      - {ip}\n"
        
        if data.get('locations'):
            report += "    • Locations:\n"
            for loc in data['locations']:
                report += f"      - {loc}\n"
        
        report += f"""
{Fore.CYAN}[+] Personal Data:{Style.RESET_ALL}
    • Birthdays: {', '.join(data.get('birthdays', ['Not found']))}
    • Password Hashes Found: {len(data.get('passwords', []))}

{Fore.CYAN}[+] Breach Data:{Style.RESET_ALL}
"""
        
        for breach in data.get('breach_data', []):
            report += f"    • {breach.get('source', 'Unknown')}:\n"
            report += f"      Email: {breach.get('email', 'N/A')}\n"
            report += f"      Password Hash: {breach.get('password_hash', 'N/A')[:20]}...\n"
        
        report += f"""
{Fore.CYAN}[+] Social Connections:{Style.RESET_ALL}
"""
        
        for conn in data.get('social_connections', []):
            report += f"    • {conn.get('platform', 'Unknown')}: {conn.get('username', 'N/A')}\n"
        
        # Save report to file
        filename = f"intel_report_{data.get('target', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(report)
        
        print(f"{Fore.GREEN}[+] Report saved to: {filename}{Style.RESET_ALL}")
        
        return report
    
    def run_scan(self, target, platform='all'):
        """Main scanning function"""
        print(f"{Fore.YELLOW}[*] Starting intelligence gathering for: {target}{Style.RESET_ALL}")
        
        self.results['target'] = target
        self.results['platform'] = platform
        self.results['timestamp'] = datetime.now().isoformat()
        
        # Step 1: Search local database
        print(f"{Fore.CYAN}[1] Searching local breach database...{Style.RESET_ALL}")
        local_results = self.search_local_db(target)
        
        for result in local_results:
            if result.get('email'):
                self.results['email'] = result['email']
            if result.get('phone'):
                self.results['phone'] = result['phone']
            if result.get('ip_address'):
                self.results['ip_addresses'].append(result['ip_address'])
            if result.get('location'):
                self.results['locations'].append(result['location'])
            if result.get('birthday'):
                self.results['birthdays'].append(result['birthday'])
            if result.get('password_hash'):
                self.results['passwords'].append(result['password_hash'])
            
            self.results['breach_data'].append(result)
        
        # Step 2: Query external sources
        print(f"{Fore.CYAN}[2] Querying external breach databases...{Style.RESET_ALL}")
        external_data = self.query_external_apis(target)
        self.results['breach_data'].extend(external_data)
        
        # Step 3: Social media extraction
        if platform != 'all':
            print(f"{Fore.CYAN}[3] Extracting from {platform}...{Style.RESET_ALL}")
            social_data = self.extract_from_social_media(target, platform)
            
            if social_data.get('email'):
                self.results['email'] = social_data['email']
            if social_data.get('phone'):
                self.results['phone'] = social_data['phone']
            if social_data.get('location'):
                self.results['locations'].append(social_data['location'])
        
        # Step 4: Email intelligence
        if '@' in target:
            print(f"{Fore.CYAN}[4] Performing email intelligence...{Style.RESET_ALL}")
            email_intel = self.reverse_email_search(target)
            self.results['social_connections'] = email_intel.get('linked_accounts', [])
        
        # Step 5: Phone intelligence
        if any(char.isdigit() for char in target) and len(target) > 7:
            print(f"{Fore.CYAN}[5] Performing phone number intelligence...{Style.RESET_ALL}")
            phone_intel = self.phone_number_intel(target)
            if phone_intel.get('location'):
                self.results['locations'].append(phone_intel['location'])
        
        # Step 6: IP lookups
        print(f"{Fore.CYAN}[6] Performing IP geolocation...{Style.RESET_ALL}")
        for ip in self.results['ip_addresses']:
            if ip and ip != 'N/A':
                ip_info = self.ip_lookup(ip)
                if ip_info.get('city'):
                    self.results['locations'].append(f"{ip_info['city']}, {ip_info['country']}")
        
        # Remove duplicates
        self.results['ip_addresses'] = list(set(self.results['ip_addresses']))
        self.results['locations'] = list(set(self.results['locations']))
        self.results['birthdays'] = list(set(self.results['birthdays']))
        
        print(f"{Fore.GREEN}[+] Intelligence gathering complete!{Style.RESET_ALL}")
        
        # Generate and display report
        report = self.generate_report(self.results)
        print(report)
        
        return self.results
    
    def interactive_mode(self):
        """Interactive command-line interface"""
        self.banner()
        
        while True:
            print(f"\n{Fore.CYAN}SHΔDØW CORE Menu:{Style.RESET_ALL}")
            print("1. Scan Facebook user")
            print("2. Scan Instagram user")
            print("3. Scan TikTok user")
            print("4. Scan by email/phone")
            print("5. View saved reports")
            print("6. Update breach database")
            print("7. Exit")
            
            choice = input(f"\n{Fore.YELLOW}[?] Select option (1-7): {Style.RESET_ALL}")
            
            if choice == '1':
                username = input(f"{Fore.YELLOW}[?] Facebook username: {Style.RESET_ALL}")
                self.run_scan(username, 'facebook')
            
            elif choice == '2':
                username = input(f"{Fore.YELLOW}[?] Instagram username: {Style.RESET_ALL}")
                self.run_scan(username, 'instagram')
            
            elif choice == '3':
                username = input(f"{Fore.YELLOW}[?] TikTok username: {Style.RESET_ALL}")
                self.run_scan(username, 'tiktok')
            
            elif choice == '4':
                identifier = input(f"{Fore.YELLOW}[?] Enter email or phone: {Style.RESET_ALL}")
                self.run_scan(identifier, 'all')
            
            elif choice == '5':
                self.view_saved_reports()
            
            elif choice == '6':
                self.update_database()
            
            elif choice == '7':
                print(f"{Fore.RED}[!] Exiting SHΔDØW CORE...{Style.RESET_ALL}")
                self.db_conn.close()
                sys.exit(0)
            
            else:
                print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
    
    def view_saved_reports(self):
        """View previously generated reports"""
        reports = [f for f in os.listdir('.') if f.startswith('intel_report_')]
        
        if not reports:
            print(f"{Fore.YELLOW}[!] No saved reports found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Saved Reports:{Style.RESET_ALL}")
        for i, report in enumerate(reports, 1):
            print(f"{i}. {report}")
        
        choice = input(f"\n{Fore.YELLOW}[?] Select report to view (or 0 to cancel): {Style.RESET_ALL}")
        
        if choice.isdigit() and 1 <= int(choice) <= len(reports):
            with open(reports[int(choice)-1], 'r') as f:
                print(f.read())
    
    def update_database(self):
