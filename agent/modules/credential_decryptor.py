#!/usr/bin/env python3
"""
Automatic Credential Decryptor Module
Decrypts various encoding types found in credential dump results
"""

import base64
import json
import re
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

class CredentialDecryptor:
    def __init__(self):
        self.decryption_methods = [
            self._try_base64_decode,
            self._try_unicode_decode,
            self._try_url_decode,
            self._try_hex_decode,
            self._try_rot13_decode,
            self._try_reverse_decode,
            self._try_xor_decode,
            self._try_common_encodings
        ]
        
        # Common XOR keys to try
        self.xor_keys = [
            b'key', b'secret', b'password', b'admin', b'root',
            b'123', b'abc', b'test', b'default', b'user',
            b'windows', b'linux', b'system', b'security'
        ]
        
        # Common encoding patterns
        self.encoding_patterns = {
            'base64': r'^[A-Za-z0-9+/]*={0,2}$',
            'hex': r'^[0-9a-fA-F]+$',
            'unicode_escape': r'\\u[0-9a-fA-F]{4}',
            'url_encoded': r'%[0-9a-fA-F]{2}',
            'rot13': r'^[a-zA-Z]+$',
            'reverse': r'^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};\':",.<>?/\\|`~]+$'
        }
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def decrypt_credential(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt a single credential using multiple methods
        """
        target = credential.get('target', '')
        username = credential.get('username', '')
        password = credential.get('password', '')
        cred_type = credential.get('type', 1)
        
        decrypted = {
            'target': target,
            'username': username,
            'original_password': password,
            'decrypted_password': password,
            'decryption_method': 'none',
            'decryption_success': False,
            'credential_type': cred_type,
            'analysis': {}
        }
        
        if not password:
            decrypted['analysis']['note'] = 'No password to decrypt'
            return decrypted
        
        # Try all decryption methods
        for method in self.decryption_methods:
            try:
                result = method(password)
                if result and result != password:
                    decrypted['decrypted_password'] = result
                    decrypted['decryption_method'] = method.__name__.replace('_try_', '').replace('_decode', '')
                    decrypted['decryption_success'] = True
                    decrypted['analysis']['decryption_note'] = f'Successfully decrypted using {decrypted["decryption_method"]}'
                    break
            except Exception as e:
                self.logger.debug(f"Method {method.__name__} failed: {e}")
                continue
        
        # Analyze the credential
        decrypted['analysis'].update(self._analyze_credential(target, username, decrypted['decrypted_password']))
        
        return decrypted
    
    def decrypt_credential_dump(self, dump_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt an entire credential dump result
        """
        decrypted_dump = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'original_data': dump_data,
            'decrypted_credentials': [],
            'summary': {
                'total_credentials': 0,
                'successfully_decrypted': 0,
                'failed_decryptions': 0,
                'credential_types': {},
                'targets': {}
            }
        }
        
        try:
            # Extract credentials from different locations in the dump
            credentials = []
            
            # Windows credentials
            if 'windows_credentials' in dump_data.get('data', {}):
                win_creds = dump_data['data']['windows_credentials']
                if 'credentials' in win_creds:
                    credentials.extend(win_creds['credentials'])
            
            # Direct credentials in data
            if 'credentials' in dump_data.get('data', {}):
                credentials.extend(dump_data['data']['credentials'])
            
            # Process each credential
            for cred in credentials:
                decrypted_cred = self.decrypt_credential(cred)
                decrypted_dump['decrypted_credentials'].append(decrypted_cred)
                
                # Update summary
                decrypted_dump['summary']['total_credentials'] += 1
                if decrypted_cred['decryption_success']:
                    decrypted_dump['summary']['successfully_decrypted'] += 1
                else:
                    decrypted_dump['summary']['failed_decryptions'] += 1
                
                # Track credential types
                cred_type = decrypted_cred['credential_type']
                decrypted_dump['summary']['credential_types'][cred_type] = decrypted_dump['summary']['credential_types'].get(cred_type, 0) + 1
                
                # Track targets
                target = decrypted_cred['target']
                if target not in decrypted_dump['summary']['targets']:
                    decrypted_dump['summary']['targets'][target] = []
                decrypted_dump['summary']['targets'][target].append(decrypted_cred['username'])
            
            # Add security insights
            decrypted_dump['security_insights'] = self._generate_security_insights(decrypted_dump['decrypted_credentials'])
            
        except Exception as e:
            decrypted_dump['status'] = 'error'
            decrypted_dump['error'] = str(e)
            self.logger.error(f"Error decrypting credential dump: {e}")
        
        return decrypted_dump
    
    def _try_base64_decode(self, data: str) -> Optional[str]:
        """Try Base64 decoding"""
        if not data or not isinstance(data, str):
            return None
        
        # Check if it looks like base64
        if not re.match(self.encoding_patterns['base64'], data):
            return None
        
        try:
            decoded = base64.b64decode(data).decode('utf-8')
            # Check if decoded result is printable
            if decoded.isprintable() and len(decoded) > 0:
                return decoded
        except Exception:
            pass
        return None
    
    def _try_unicode_decode(self, data: str) -> Optional[str]:
        """Try Unicode escape decoding"""
        if not data or not isinstance(data, str):
            return None
        
        # Check if it contains unicode escapes
        if '\\u' not in data:
            return None
        
        try:
            decoded = data.encode('utf-8').decode('unicode_escape')
            if decoded.isprintable() and len(decoded) > 0:
                return decoded
        except Exception:
            pass
        return None
    
    def _try_url_decode(self, data: str) -> Optional[str]:
        """Try URL decoding"""
        if not data or not isinstance(data, str):
            return None
        
        # Check if it contains URL encoded characters
        if '%' not in data:
            return None
        
        try:
            import urllib.parse
            decoded = urllib.parse.unquote(data)
            if decoded != data:
                return decoded
        except Exception:
            pass
        return None
    
    def _try_hex_decode(self, data: str) -> Optional[str]:
        """Try hexadecimal decoding"""
        if not data or not isinstance(data, str):
            return None
        
        # Check if it looks like hex
        if not re.match(self.encoding_patterns['hex'], data):
            return None
        
        try:
            decoded = bytes.fromhex(data).decode('utf-8')
            if decoded.isprintable() and len(decoded) > 0:
                return decoded
        except Exception:
            pass
        return None
    
    def _try_rot13_decode(self, data: str) -> Optional[str]:
        """Try ROT13 decoding"""
        if not data or not isinstance(data, str):
            return None
        
        # Check if it's only letters
        if not re.match(self.encoding_patterns['rot13'], data):
            return None
        
        try:
            decoded = data.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            if decoded != data:
                return decoded
        except Exception:
            pass
        return None
    
    def _try_reverse_decode(self, data: str) -> Optional[str]:
        """Try reverse string decoding"""
        if not data or not isinstance(data, str):
            return None
        
        # Check if it might be reversed
        if len(data) < 3:
            return None
        
        try:
            reversed_data = data[::-1]
            # Check if reversed looks more like a password
            if self._looks_like_password(reversed_data) and not self._looks_like_password(data):
                return reversed_data
        except Exception:
            pass
        return None
    
    def _try_xor_decode(self, data: str) -> Optional[str]:
        """Try XOR decoding with common keys"""
        if not data or not isinstance(data, str):
            return None
        
        try:
            data_bytes = data.encode('utf-8')
            for key in self.xor_keys:
                try:
                    decoded = bytes(a ^ b for a, b in zip(data_bytes, key * (len(data_bytes) // len(key) + 1)))
                    decoded_str = decoded.decode('utf-8', errors='ignore')
                    if decoded_str.isprintable() and len(decoded_str) > 0:
                        return decoded_str
                except Exception:
                    continue
        except Exception:
            pass
        return None
    
    def _try_common_encodings(self, data: str) -> Optional[str]:
        """Try other common encoding methods"""
        if not data or not isinstance(data, str):
            return None
        
        # Try different encodings
        encodings = ['latin1', 'cp1252', 'iso-8859-1', 'utf-16', 'utf-32']
        
        for encoding in encodings:
            try:
                # Try to decode as if it's bytes in this encoding
                decoded = data.encode('latin1').decode(encoding)
                if decoded != data and decoded.isprintable():
                    return decoded
            except Exception:
                continue
        
        return None
    
    def _looks_like_password(self, text: str) -> bool:
        """Check if text looks like a password"""
        if not text:
            return False
        
        # Check for common password patterns
        has_letters = any(c.isalpha() for c in text)
        has_numbers = any(c.isdigit() for c in text)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in text)
        
        # Password-like characteristics
        if has_letters and has_numbers:
            return True
        if has_letters and has_special:
            return True
        if has_numbers and has_special:
            return True
        
        return False
    
    def _analyze_credential(self, target: str, username: str, password: str) -> Dict[str, Any]:
        """Analyze a credential for security insights"""
        analysis = {
            'target_type': self._classify_target(target),
            'username_analysis': self._analyze_username(username),
            'password_strength': self._analyze_password_strength(password),
            'security_risk': 'low',
            'recommendations': []
        }
        
        # Determine security risk
        if analysis['password_strength'] == 'weak':
            analysis['security_risk'] = 'high'
            analysis['recommendations'].append('Password is weak - recommend immediate change')
        elif analysis['password_strength'] == 'medium':
            analysis['security_risk'] = 'medium'
            analysis['recommendations'].append('Password could be stronger')
        
        # Check for common weak patterns
        if password.lower() in ['password', 'admin', 'root', '123456', 'qwerty']:
            analysis['security_risk'] = 'critical'
            analysis['recommendations'].append('CRITICAL: Using extremely weak password')
        
        # Check for business accounts
        if any(domain in target.lower() for domain in ['sharepoint', 'onedrive', 'office365', 'microsoft']):
            analysis['security_risk'] = 'high'
            analysis['recommendations'].append('Business account - high value target')
        
        return analysis
    
    def _classify_target(self, target: str) -> str:
        """Classify the target type"""
        target_lower = target.lower()
        
        if 'docker' in target_lower:
            return 'Docker Hub'
        elif 'github' in target_lower:
            return 'GitHub'
        elif 'sharepoint' in target_lower or 'onedrive' in target_lower:
            return 'Microsoft 365'
        elif 'http' in target_lower:
            return 'Web Service'
        elif 'git:' in target_lower:
            return 'Git Repository'
        else:
            return 'Unknown'
    
    def _analyze_username(self, username: str) -> Dict[str, Any]:
        """Analyze username characteristics"""
        if not username:
            return {'type': 'none', 'characteristics': []}
        
        analysis = {
            'type': 'standard',
            'characteristics': [],
            'length': len(username)
        }
        
        if username.isdigit():
            analysis['type'] = 'numeric'
        elif '@' in username:
            analysis['type'] = 'email'
        elif username.startswith('gho_'):
            analysis['type'] = 'github_token'
        elif len(username) == 36 and '-' in username:
            analysis['type'] = 'uuid'
        
        # Add characteristics
        if username.islower():
            analysis['characteristics'].append('all_lowercase')
        if username.isupper():
            analysis['characteristics'].append('all_uppercase')
        if any(c.isdigit() for c in username):
            analysis['characteristics'].append('contains_numbers')
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in username):
            analysis['characteristics'].append('contains_special_chars')
        
        return analysis
    
    def _analyze_password_strength(self, password: str) -> str:
        """Analyze password strength"""
        if not password:
            return 'none'
        
        score = 0
        length = len(password)
        
        # Length score
        if length >= 12:
            score += 3
        elif length >= 8:
            score += 2
        elif length >= 6:
            score += 1
        
        # Character variety score
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        if has_lower:
            score += 1
        if has_upper:
            score += 1
        if has_digit:
            score += 1
        if has_special:
            score += 1
        
        # Determine strength
        if score >= 6:
            return 'strong'
        elif score >= 4:
            return 'medium'
        elif score >= 2:
            return 'weak'
        else:
            return 'very_weak'
    
    def _generate_security_insights(self, credentials: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate security insights from decrypted credentials"""
        insights = {
            'critical_findings': [],
            'high_risk_targets': [],
            'weak_passwords': [],
            'business_accounts': [],
            'recommendations': []
        }
        
        for cred in credentials:
            target = cred['target']
            password = cred['decrypted_password']
            analysis = cred.get('analysis', {})
            
            # Check for critical issues
            if analysis.get('security_risk') == 'critical':
                insights['critical_findings'].append({
                    'target': target,
                    'username': cred['username'],
                    'issue': 'Extremely weak password detected'
                })
            
            # Check for high-risk targets
            if analysis.get('security_risk') == 'high':
                insights['high_risk_targets'].append({
                    'target': target,
                    'username': cred['username'],
                    'reason': analysis.get('recommendations', ['High security risk'])[0]
                })
            
            # Check for weak passwords
            if analysis.get('password_strength') in ['weak', 'very_weak']:
                insights['weak_passwords'].append({
                    'target': target,
                    'username': cred['username'],
                    'strength': analysis.get('password_strength')
                })
            
            # Check for business accounts
            if analysis.get('target_type') in ['Microsoft 365', 'SharePoint', 'OneDrive']:
                insights['business_accounts'].append({
                    'target': target,
                    'username': cred['username'],
                    'type': analysis.get('target_type')
                })
        
        # Generate recommendations
        if insights['critical_findings']:
            insights['recommendations'].append('Immediately change all critical weak passwords')
        if insights['high_risk_targets']:
            insights['recommendations'].append('Review and secure high-risk accounts')
        if insights['weak_passwords']:
            insights['recommendations'].append('Implement password policy for weak passwords')
        if insights['business_accounts']:
            insights['recommendations'].append('Review business account security policies')
        
        return insights

def decrypt_credentials_auto(credential_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main function to automatically decrypt credential data
    """
    try:
        decryptor = CredentialDecryptor()
        
        if 'data' in credential_data and 'windows_credentials' in credential_data['data']:
            # Full credential dump
            return decryptor.decrypt_credential_dump(credential_data)
        else:
            # Single credential or different format
            return decryptor.decrypt_credential(credential_data)
            
    except Exception as e:
        return {
            'status': 'error',
            'error': f'Decryption failed: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }

# Example usage
if __name__ == "__main__":
    # Test the decryptor
    test_credential = {
        "target": "https://index.docker.io/v1/",
        "username": "wsratul517",
        "password": "wsratul_2l0s8D4-T7t-PLq6V4tU7",
        "type": 1
    }
    
    result = decrypt_credentials_auto(test_credential)
    print(json.dumps(result, indent=2))
