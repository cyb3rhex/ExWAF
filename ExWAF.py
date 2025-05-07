"""
ExWAF - exchange web application firewall - Mustafa Hussein
copyright (c) 2025

a robust, lightweight waf specifically designed to protect microsoft exchange owa
from common web attacks, including xss, sql injection, and brute force attempts.
"""

import http.server
import socketserver
import urllib.request
import urllib.error
import re
import json
import logging
import os
import sys
import time
import ipaddress
from http import cookies
from urllib.parse import urlparse, parse_qs

# configuration
EXCHANGE_SERVER = "https://localhost"  # your actual owa server
PORT = 8080  # the port exwaf will listen on
LOG_FILE = "exwaf.log"
BLOCKED_IPS_FILE = "blocked_ips.json"
MAX_REQUESTS_PER_MINUTE = 30

# setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# keep track of requests per ip
request_counts = {}
blocked_ips = {}

# load blocked ips if file exists
if os.path.exists(BLOCKED_IPS_FILE):
    try:
        with open(BLOCKED_IPS_FILE, 'r') as f:
            blocked_ips = json.load(f)
    except Exception as e:
        logging.error(f"Failed to load blocked IPs: {e}")

# regular expressions for detecting attacks
XSS_PATTERNS = [
    r'<script.*?>',
    r'javascript:',
    r'onerror=',
    r'onload=',
    r'eval\(',
    r'document\.cookie',
    r'alert\(',
    r'token=.*[<>]',  # specific check for 2fa token manipulation
]

SQL_INJECTION_PATTERNS = [
    r'(\s|^)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)(\s)',
    r'(UNION|JOIN).*SELECT',
    r"(\s|^|')--",
    r'\/\*.*\*\/',
    r';\s*(\w+|$)',
    r"'\s*OR\s*'.*'='",
    r'"\s*OR\s*".*"="',
]

def save_blocked_ips():
    """save blocked ips to file"""
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_ips, f)
    except Exception as e:
        logging.error(f"Failed to save blocked IPs: {e}")

def is_ip_blocked(ip):
    """check if ip is blocked"""
    if ip in blocked_ips:
        block_until = blocked_ips[ip]
        if block_until == "permanent" or time.time() < float(block_until):
            return True
        else:
            # remove expired blocks
            del blocked_ips[ip]
            save_blocked_ips()
    return False

def block_ip(ip, duration=3600):
    """block an ip for a specified duration or permanently"""
    if duration == "permanent":
        blocked_ips[ip] = "permanent"
    else:
        blocked_ips[ip] = time.time() + duration
    save_blocked_ips()
    logging.warning(f"Blocked IP {ip} for {duration}")

def contains_attack_patterns(data, patterns):
    """check if any attack patterns are in the data"""
    if not data:
        return False
    
    data_str = str(data).lower()
    for pattern in patterns:
        if re.search(pattern, data_str, re.IGNORECASE):
            return True
    return False

def is_xss_attack(data):
    """check for xss attacks"""
    return contains_attack_patterns(data, XSS_PATTERNS)

def is_sql_injection(data):
    """check for sql injection attacks"""
    return contains_attack_patterns(data, SQL_INJECTION_PATTERNS)

class ExchangeWAFHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """override to log to our file instead of stderr"""
        logging.info(f"{self.client_address[0]} - {format % args}")

    def rate_limit(self):
        """implement rate limiting per ip"""
        client_ip = self.client_address[0]
        current_time = time.time()
        minute_ago = current_time - 60
        
        # initialize if this is a new ip
        if client_ip not in request_counts:
            request_counts[client_ip] = []
        
        # clean old requests
        request_counts[client_ip] = [t for t in request_counts[client_ip] if t > minute_ago]
        
        # add current request
        request_counts[client_ip].append(current_time)
        
        # check if too many requests
        if len(request_counts[client_ip]) > MAX_REQUESTS_PER_MINUTE:
            block_ip(client_ip, 600)  # block for 10 minutes
            return True
        
        return False

    def check_security(self):
        """check for security threats"""
        client_ip = self.client_address[0]
        
        # check if ip is blocked
        if is_ip_blocked(client_ip):
            self.send_error(403, "Forbidden - Your IP is blocked")
            return False
        
        # apply rate limiting
        if self.rate_limit():
            self.send_error(429, "Too Many Requests")
            return False
        
        # Get request data for inspection
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = None
        if content_length > 0:
            post_data = self.rfile.read(content_length).decode('utf-8')
            # Reset file pointer for later reads
            self.rfile.seek(0)
        
        # Check URL parameters for attacks
        url_parts = urlparse(self.path)
        query_params = parse_qs(url_parts.query)
        
        # Check cookies
        cookies_str = self.headers.get('Cookie', '')
        
        # Check all data sources for attacks
        data_to_check = [
            self.path,
            post_data,
            str(query_params),
            cookies_str,
            str(self.headers)
        ]
        
        for data in data_to_check:
            if data:
                if is_xss_attack(data):
                    logging.warning(f"XSS attack detected from {client_ip}: {data}")
                    block_ip(client_ip, 3600)  # Block for 1 hour
                    self.send_error(403, "Forbidden - XSS Attack Detected")
                    return False
                
                if is_sql_injection(data):
                    logging.warning(f"SQL injection attack detected from {client_ip}: {data}")
                    block_ip(client_ip, 3600)  # Block for 1 hour
                    self.send_error(403, "Forbidden - SQL Injection Attack Detected")
                    return False
        
        # Special handling for OWA login
        if "/owa/auth" in self.path or "/owa/auth.owa" in self.path:
            logging.info(f"OWA login attempt from {client_ip}")
            
            # Extra checks for login inputs
            if post_data and ('username' in post_data or 'password' in post_data):
                # Log username (but not password) for security monitoring
                username_match = re.search(r'username=([^&]+)', post_data)
                if username_match:
                    sanitized_username = re.sub(r'[<>"\';&]', '', username_match.group(1))
                    logging.info(f"Login attempt with username {sanitized_username}")
        
        # Special handling for Fortinet 2FA login page
        if "/fortinet/login2fa" in self.path:
            logging.info(f"2FA login attempt from {client_ip}")
            
            # Extra sanitization for 2FA tokens
            if post_data and ("token" in post_data or "pin" in post_data or "otp" in post_data):
                # Check for numeric-only OTP/PIN (most 2FA uses numeric tokens)
                token_match = re.search(r'token=([^&]+)', post_data) or re.search(r'otp=([^&]+)', post_data)
                if token_match and not re.match(r'^\d+$', token_match.group(1)):
                    logging.warning(f"Potentially malicious 2FA token from {client_ip}")
                    block_ip(client_ip, 1800)  # Block for 30 minutes
                    self.send_error(403, "Forbidden - Invalid 2FA Token Format")
                    return False
        
        return True

    def proxy_request(self, method):
        """Proxy the request to the Exchange server"""
        if not self.check_security():
            return
        
        # Build target URL
        target_url = EXCHANGE_SERVER + self.path
        
        try:
            # Create request
            request = urllib.request.Request(
                target_url,
                method=method
            )
            
            # Copy headers
            for header in self.headers:
                if header.lower() not in ('host', 'connection'):
                    request.add_header(header, self.headers[header])
            
            # Add body for POST requests
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                request.data = post_data
            
            # Send request to Exchange server
            with urllib.request.urlopen(request) as response:
                # Send response code
                self.send_response(response.status)
                
                # Copy response headers
                for header in response.headers:
                    if header.lower() != 'transfer-encoding':
                        self.send_header(header, response.headers[header])
                
                # Add security headers
                self.send_header('X-XSS-Protection', '1; mode=block')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('X-Frame-Options', 'SAMEORIGIN')
                self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'")
                
                self.end_headers()
                
                # Send response body
                self.wfile.write(response.read())
            
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            logging.error(f"Proxy error: {e}")
            self.send_error(500, f"Proxy Error: {str(e)}")

    def do_GET(self):
        self.proxy_request('GET')

    def do_POST(self):
        self.proxy_request('POST')

    def do_HEAD(self):
        self.proxy_request('HEAD')

def print_status():
    """Print WAF status information"""
    print("\n=== ExWAF - Exchange Web Application Firewall ===")
    print(f"Version 1.0.0")
    print(f"Proxy forwarding to: {EXCHANGE_SERVER}")
    print(f"Listening on port: {PORT}")
    print(f"Log file: {LOG_FILE}")
    
    # Active blocks
    active_blocks = 0
    permanent_blocks = 0
    for ip, until in blocked_ips.items():
        if until == "permanent":
            permanent_blocks += 1
        elif time.time() < float(until):
            active_blocks += 1
    
    print(f"Blocked IPs: {active_blocks} temporary, {permanent_blocks} permanent")
    print("=============================================\n")

def start_server():
    """Start the WAF server"""
    try:
        print_status()
        print("Starting Exchange Web Application Firewall...")
        print(f"Listening on port {PORT}")
        print("Press Ctrl+C to stop")
        
        server = socketserver.ThreadingTCPServer(('', PORT), ExchangeWAFHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()
        print("Server stopped")
    except Exception as e:
        logging.error(f"Server error: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    start_server() 