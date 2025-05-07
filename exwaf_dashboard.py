"""
ExWAF dashboard - exchange web application firewall monitoring interface
copyright (c) 2025 - Mustafa Hussein

this dashboard provides a monitoring interface for the exwaf security solution.
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
import os
import json
import time
import datetime
import re
import ipaddress
import threading
from collections import Counter, defaultdict

app = Flask(__name__)
app.secret_key = os.urandom(24)

# configuration settings
LOG_FILE = "exwaf.log"
BLOCKED_IPS_FILE = "blocked_ips.json"
DASHBOARD_PORT = 8081
DATA_REFRESH_INTERVAL = 30  # seconds

# global data storage
waf_stats = {}
blocked_ips = {}
top_ips = []
hourly_stats = []
attack_timeline = []
last_refresh = None

def extract_ip_from_log(line):
    """extract ip address from a log line using multiple patterns"""
    # standard pattern: ip: x.x.x.x
    ip_match = re.search(r'IP: (\d+\.\d+\.\d+\.\d+)', line)
    if ip_match:
        return ip_match.group(1)
    
    # format like: x.x.x.x - code
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+) - code', line)
    if ip_match:
        return ip_match.group(1)
    
    # format with: from x.x.x.x
    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
    if ip_match:
        return ip_match.group(1)
    
    return None

def load_blocked_ips():
    """load blocked ips from the json file"""
    try:
        if os.path.exists(BLOCKED_IPS_FILE) and os.path.getsize(BLOCKED_IPS_FILE) > 0:
            try:
                with open(BLOCKED_IPS_FILE, 'r') as f:
                    data = json.load(f)
                # validate that the data looks right
                # if any entries aren't dictionaries with needed fields, fix them
                for ip, ip_data in list(data.items()):
                    if not isinstance(ip_data, dict):
                        # convert old format (float timestamps) to proper format
                        data[ip] = {
                            'count': 1,
                            'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'status': 'active',
                            'expires': 'Never',
                            'reason': 'Security violation'
                        }
                return data
            except Exception as e:
                print(f"error - failed to load blocked ips: {str(e)}")
                # if file exists but is corrupted, make a fresh one
                with open(BLOCKED_IPS_FILE, 'w') as f:
                    json.dump({}, f)
                return {}
        else:
            # if file doesn't exist or is empty, create it
            with open(BLOCKED_IPS_FILE, 'w') as f:
                json.dump({}, f)
            return {}
    except Exception as e:
        print(f"error - exception in load_blocked_ips: {str(e)}")
        return {}

def save_blocked_ips():
    """save blocked ips to the json file"""
    with open(BLOCKED_IPS_FILE, 'w') as f:
        json.dump(blocked_ips, f, indent=4)

def parse_log_data():
    """parse the log file and update global stats"""
    global waf_stats, blocked_ips, top_ips, hourly_stats, attack_timeline, last_refresh
    
    # initialize stats
    waf_stats = {
        'total_requests': 0,
        'blocked_requests': 0,
        'xss_attempts': 0,
        'sql_attacks': 0,
        'rate_limited': 0,
        'last_updated': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'recent_events': [],
        'hourly_stats': [],
        'top_ips': [],
        'attack_timeline': []
    }
    
    # try to load blocked ips from file first
    file_blocked_ips = load_blocked_ips()
    if file_blocked_ips:
        blocked_ips = file_blocked_ips
    else:
        blocked_ips = {}
    
    ip_counter = Counter()
    hourly_data = defaultdict(int)
    attack_events = []
    
    if not os.path.exists(LOG_FILE):
        return
    
    with open(LOG_FILE, 'r') as f:
        for line in f:
            # count total requests if this is an incoming request (not internal logs)
            if "GET " in line or "POST " in line:
                waf_stats['total_requests'] += 1
            
            # extract timestamp for hourly stats
            timestamp_match = re.match(r'^(.*?) -', line)
            timestamp_str = timestamp_match.group(1) if timestamp_match else 'Unknown'
            
            if timestamp_match:
                try:
                    timestamp = datetime.datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S,%f')
                    hour_key = timestamp.strftime('%H:00')
                    hourly_data[hour_key] += 1
                except:
                    pass
            
            # extract ip from the log line
            ip = extract_ip_from_log(line)
            
            if ip:
                ip_counter[ip] += 1
            
            # track xss attacks
            if "XSS attack detected" in line or "XSS Attack Detected" in line:
                waf_stats['xss_attempts'] += 1
                waf_stats['blocked_requests'] += 1
                
                # if no ip found yet, look for special xss pattern
                if not ip:
                    xss_ip_match = re.search(r'XSS attack detected from (\d+\.\d+\.\d+\.\d+)', line)
                    if xss_ip_match:
                        ip = xss_ip_match.group(1)
                
                if ip:
                    # update blocked ips - check ip exists and is a dictionary
                    if ip not in blocked_ips:
                        blocked_ips[ip] = {
                            'count': 1,
                            'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'status': 'active',
                            'expires': 'Never',
                            'reason': 'XSS Attack'
                        }
                    else:
                        # check if blocked_ips[ip] is a dictionary before using its keys
                        if isinstance(blocked_ips[ip], dict):
                            blocked_ips[ip]['count'] += 1
                            blocked_ips[ip]['last_seen'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            # if it's not a dictionary, recreate it properly
                            blocked_ips[ip] = {
                                'count': 1,
                                'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'status': 'active',
                                'expires': 'Never',
                                'reason': 'XSS Attack'
                            }
                    
                    # record the attack event
                    attack_events.append({
                        'time': timestamp_str,
                        'type': 'XSS Attack',
                        'ip': ip
                    })
            
            # track sql injection attacks  
            elif "SQL injection" in line.lower() or "SQL Injection" in line:
                waf_stats['sql_attacks'] += 1
                waf_stats['blocked_requests'] += 1
                
                if ip:
                    # update blocked ips - check ip exists and is a dictionary
                    if ip not in blocked_ips:
                        blocked_ips[ip] = {
                            'count': 1,
                            'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'status': 'active',
                            'expires': 'Never',
                            'reason': 'SQL Injection'
                        }
                    else:
                        # check if blocked_ips[ip] is a dictionary before using its keys
                        if isinstance(blocked_ips[ip], dict):
                            blocked_ips[ip]['count'] += 1
                            blocked_ips[ip]['last_seen'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            # if it's not a dictionary, recreate it properly
                            blocked_ips[ip] = {
                                'count': 1,
                                'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'status': 'active',
                                'expires': 'Never',
                                'reason': 'SQL Injection'
                            }
                    
                    # record the attack event
                    attack_events.append({
                        'time': timestamp_str,
                        'type': 'SQL Injection',
                        'ip': ip
                    })
            
            # track rate limiting
            elif "Rate limited" in line or "Too Many Requests" in line:
                waf_stats['rate_limited'] += 1
                waf_stats['blocked_requests'] += 1
                
                if ip:
                    # update blocked ips - check ip exists and is a dictionary
                    if ip not in blocked_ips:
                        blocked_ips[ip] = {
                            'count': 1,
                            'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'status': 'active',
                            'expires': 'Never',
                            'reason': 'Rate Limit Exceeded'
                        }
                    else:
                        # check if blocked_ips[ip] is a dictionary before using its keys
                        if isinstance(blocked_ips[ip], dict):
                            blocked_ips[ip]['count'] += 1
                            blocked_ips[ip]['last_seen'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            # if it's not a dictionary, recreate it properly
                            blocked_ips[ip] = {
                                'count': 1,
                                'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'status': 'active',
                                'expires': 'Never',
                                'reason': 'Rate Limit Exceeded'
                            }
                    
                    # record the attack event
                    attack_events.append({
                        'time': timestamp_str,
                        'type': 'Rate Limit',
                        'ip': ip
                    })
            
            # track ip blocks
            elif "Blocked IP" in line:
                ip_match = re.search(r'Blocked IP (\d+\.\d+\.\d+\.\d+)', line)
                duration_match = re.search(r'for (\d+)', line)
                
                if ip_match:
                    block_ip = ip_match.group(1)
                    duration = "Never"
                    
                    if duration_match:
                        try:
                            seconds = int(duration_match.group(1))
                            hours = seconds / 3600  # convert seconds to hours
                            expire_time = datetime.datetime.now() + datetime.timedelta(seconds=seconds)
                            duration = expire_time.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                    
                    # update blocked ips - check ip exists and is a dictionary
                    if block_ip not in blocked_ips:
                        blocked_ips[block_ip] = {
                            'count': 1,
                            'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'status': 'active',
                            'expires': duration,
                            'reason': 'Security violation'
                        }
                    else:
                        # check if blocked_ips[ip] is a dictionary before using its keys
                        if isinstance(blocked_ips[block_ip], dict):
                            blocked_ips[block_ip]['count'] += 1
                            blocked_ips[block_ip]['last_seen'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            # if it's not a dictionary, recreate it properly
                            blocked_ips[block_ip] = {
                                'count': 1,
                                'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'status': 'active',
                                'expires': duration,
                                'reason': 'Security violation'
                            }
                        
                    waf_stats['blocked_requests'] += 1
            
            # track "ip is blocked" messages
            elif "IP is blocked" in line or "Forbidden - Your IP is blocked" in line:
                # extract ip from line
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+) - code 403', line)
                if ip_match:
                    block_ip = ip_match.group(1)
                    
                    # update blocked ips - check ip exists and is a dictionary
                    if block_ip not in blocked_ips:
                        blocked_ips[block_ip] = {
                            'count': 1,
                            'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'status': 'active',
                            'expires': 'Never',
                            'reason': 'Security violation'
                        }
                    else:
                        # check if blocked_ips[ip] is a dictionary before using its keys
                        if isinstance(blocked_ips[block_ip], dict):
                            blocked_ips[block_ip]['count'] += 1
                            blocked_ips[block_ip]['last_seen'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            # if it's not a dictionary, recreate it properly
                            blocked_ips[block_ip] = {
                                'count': 1,
                                'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'status': 'active',
                                'expires': 'Never',
                                'reason': 'Security violation'
                            }
                        
                    waf_stats['blocked_requests'] += 1
            
            # track recent events (last 20)
            if len(waf_stats['recent_events']) < 20:
                try:
                    parts = line.strip().split(" - ", 1)
                    if len(parts) > 1:
                        timestamp = parts[0].strip()
                        message = parts[1].strip()
                        
                        # figure out log level based on content
                        level = 'INFO'
                        if 'WARNING' in message or 'BLOCKED' in message or 'attack detected' in message.lower():
                            level = 'WARNING'
                        if 'ERROR' in message or 'CRITICAL' in message:
                            level = 'ERROR'
                        
                        # extract ip from message if not already found
                        event_ip = ip
                        if not event_ip and "from " in message:
                            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
                            if ip_match:
                                event_ip = ip_match.group(1)
                        
                        waf_stats['recent_events'].append({
                            'timestamp': timestamp,
                            'level': level,
                            'ip': event_ip if event_ip else 'Unknown',
                            'message': message
                        })
                except:
                    # skip any messed up log lines
                    pass
    
    # make sure blocked_requests is at least as high as the sum of attack counts
    attack_sum = waf_stats['xss_attempts'] + waf_stats['sql_attacks'] + waf_stats['rate_limited']
    waf_stats['blocked_requests'] = max(waf_stats['blocked_requests'], attack_sum)
    
    # process hourly stats (past 24 hours)
    now = datetime.datetime.now()
    hourly_stats = []
    
    for i in range(24):
        hour = (now - datetime.timedelta(hours=i)).strftime('%H:00')
        hourly_stats.append({
            'hour': hour,
            'count': hourly_data.get(hour, 0)
        })
    hourly_stats.reverse()
    waf_stats['hourly_stats'] = hourly_stats
    
    # get top ips by request count
    top_ips = ip_counter.most_common(10)
    waf_stats['top_ips'] = top_ips
    
    # get recent attack timeline
    attack_timeline = attack_events[-20:] if attack_events else []
    waf_stats['attack_timeline'] = attack_timeline
    
    # save blocked ips to file
    save_blocked_ips()
    
    # update last refresh time
    last_refresh = datetime.datetime.now()

# background refresh thread
def background_refresh():
    while True:
        parse_log_data()
        time.sleep(DATA_REFRESH_INTERVAL)

# start background refresh thread
refresh_thread = threading.Thread(target=background_refresh, daemon=True)
refresh_thread.start()

@app.route('/')
def dashboard():
    """render the main dashboard page"""
    # make sure we have data
    if not waf_stats:
        parse_log_data()
    
    # make sure rate_limited count exists
    if 'rate_limited' not in waf_stats:
        waf_stats['rate_limited'] = 0
        
    # pass all stats to the template
    return render_template(
        'dashboard.html', 
        stats=waf_stats, 
        blocked_ips=blocked_ips,
        refresh_interval=DATA_REFRESH_INTERVAL
    )

@app.route('/api/stats')
def get_stats():
    """api endpoint to get the current waf statistics"""
    if not waf_stats or (datetime.datetime.now() - last_refresh).seconds > DATA_REFRESH_INTERVAL:
        parse_log_data()
    return jsonify(waf_stats)

@app.route('/api/blocked')
def get_blocked():
    """api endpoint to get the blocked ips"""
    if not blocked_ips or (datetime.datetime.now() - last_refresh).seconds > DATA_REFRESH_INTERVAL:
        parse_log_data()
    return jsonify(blocked_ips)

@app.route('/block-ip', methods=['POST'])
def block_ip():
    """api endpoint to manually block an ip address"""
    ip = request.form.get('ip')
    duration = request.form.get('duration')
    
    # validate ip address
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid IP address format'})
    
    # calculate expiration
    expiration = "Never"
    if duration != "permanent":
        try:
            hours = int(duration)
            expire_time = datetime.datetime.now() + datetime.timedelta(hours=hours)
            expiration = expire_time.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            expiration = "Never"
    
    # update blocked ips
    blocked_ips[ip] = {
        'count': 0,
        'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'active',
        'expires': expiration,
        'reason': 'Manual block'
    }
    
    # save to file
    save_blocked_ips()
    
    # log the manual block
    with open(LOG_FILE, 'a') as f:
        log_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')
        f.write(f"{log_time} - MANUAL BLOCK: IP: {ip} manually blocked by admin\n")
    
    return jsonify({'success': True})

@app.route('/unblock-ip', methods=['POST'])
def unblock_ip():
    """api endpoint to unblock an ip address"""
    ip = request.form.get('ip')
    
    if ip in blocked_ips:
        del blocked_ips[ip]
        
        # save to file
        save_blocked_ips()
        
        # log the unblock
        with open(LOG_FILE, 'a') as f:
            log_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')
            f.write(f"{log_time} - MANUAL UNBLOCK: IP: {ip} manually unblocked by admin\n")
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'IP not found in blocked list'})

@app.route('/clear-log', methods=['POST'])
def clear_log():
    """api endpoint to clear the log file"""
    try:
        with open(LOG_FILE, 'w') as f:
            log_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')
            f.write(f"{log_time} - LOG CLEARED: Log file was cleared by admin\n")
        
        # reset stats
        global waf_stats, blocked_ips
        waf_stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'xss_attempts': 0,
            'sql_attacks': 0,
            'rate_limited': 0,
            'last_updated': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'recent_events': [],
            'hourly_stats': [],
            'top_ips': [],
            'attack_timeline': []
        }
        blocked_ips = {}
        save_blocked_ips()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

def start_dashboard():
    """start the dashboard server"""
    print(f"starting exwaf dashboard on port {DASHBOARD_PORT}...")
    # initial data parse
    parse_log_data()
    # run the app
    app.run(host='0.0.0.0', port=DASHBOARD_PORT, debug=True)

if __name__ == "__main__":
    start_dashboard() 