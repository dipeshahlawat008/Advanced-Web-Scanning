from flask import Flask, render_template, jsonify, request
from bs4 import BeautifulSoup
import requests
import threading
import queue
import time
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import logging
import socket
import whois
import ssl
import dns.resolver
from urllib.parse import urljoin
import base64
import ipaddress
import nmap  # You'll need to install python-nmap
import subprocess

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Global variables for scan state
scan_state = {
    'is_scanning': False,
    'progress': 0,
    'current_task': '',
    'results': {
        'pages': [],
        'hidden_dirs': [],
        'php_files': [],
        'encoded_data': [],
        'network_info': {},
        'vulnerabilities': []
    }
}


def reset_scan_state():
    """Reset the scan state for a new scan"""
    scan_state['is_scanning'] = False
    scan_state['progress'] = 0
    scan_state['current_task'] = ''
    scan_state['results'] = {
        'pages': [],
        'hidden_dirs': [],
        'php_files': [],
        'encoded_data': [],
        'network_info': {},
        'vulnerabilities': []
    }


def update_progress(progress, task):
    """Update scan progress and current task"""
    scan_state['progress'] = progress
    scan_state['current_task'] = task


def is_valid_url(url, base_url):
    """Check if URL is valid and belongs to same domain"""
    try:
        return urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(base_url).netloc
    except:
        return False


def get_network_info(target, options):
    """Gather comprehensive network information"""
    info = {}
    try:
        # Basic DNS Information
        if options.get('dnsEnum', False):
            info['ip'] = socket.gethostbyname(target)
            records = {}
            for qtype in ['A', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
                try:
                    answers = dns.resolver.resolve(target, qtype)
                    records[qtype] = [str(rdata) for rdata in answers]
                except:
                    records[qtype] = []
            info['dns_records'] = records
            update_progress(20, 'DNS Enumeration Complete')

        # WHOIS Information
        try:
            w = whois.whois(target)
            info['whois'] = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers
            }
        except:
            info['whois'] = None
        update_progress(40, 'WHOIS Information Retrieved')

        # SSL Certificate Information
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
                s.connect((target, 443))
                cert = s.getpeercert()
                info['ssl'] = {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert['version'],
                    'expires': cert['notAfter']
                }
        except:
            info['ssl'] = None
        update_progress(60, 'SSL Information Retrieved')

        # Port Scanning
        if options.get('portScan', False):
            port_range = options.get('portRange', '80,443,8080')
            nm = nmap.PortScanner()
            nm.scan(target, port_range)
            info['ports'] = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        info['ports'].append({
                            'port': port,
                            'state': service['state'],
                            'service': service['name']
                        })
            update_progress(80, 'Port Scan Complete')

        # Subnet Scanning
        if options.get('scanSubnet', False):
            try:
                ip = socket.gethostbyname(target)
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                info['subnet'] = []
                for ip in network.hosts():
                    if subprocess.call(['ping', '-c', '1', '-W', '1', str(ip)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                        info['subnet'].append(str(ip))
            except:
                info['subnet'] = None
            update_progress(90, 'Subnet Scan Complete')

    except Exception as e:
        logging.error(f"Error in network scanning: {str(e)}")

    return info


def directory_bruteforce(url, wordlist_path=None):
    """Perform directory bruteforce"""
    found_dirs = []
    if not wordlist_path:
        # Default small wordlist
        common_dirs = ['admin', 'backup', 'wp-admin', 'login', 'wp-content',
                       'upload', 'uploads', 'test', 'tmp', 'old']
    else:
        try:
            with open(wordlist_path, 'r') as f:
                common_dirs = [line.strip() for line in f]
        except:
            common_dirs = []

    base_url = url.rstrip('/')
    for directory in common_dirs:
        try:
            dir_url = f"{base_url}/{directory}"
            response = requests.get(dir_url, timeout=5)
            if response.status_code in [200, 301, 302, 403]:
                found_dirs.append({
                    'url': dir_url,
                    'status': response.status_code
                })
        except:
            continue

    return found_dirs


def crawl_site(url):
    """Crawl a website and extract information"""
    visited_urls = set()
    url_queue = queue.Queue()
    url_queue.put(url)

    with ThreadPoolExecutor(max_workers=5) as executor:
        while not url_queue.empty():
            current_url = url_queue.get()
            if current_url not in visited_urls:
                visited_urls.add(current_url)
                try:
                    response = requests.get(current_url, timeout=10)
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Extract links
                    for link in soup.find_all('a'):
                        href = link.get('href')
                        if href:
                            full_url = urljoin(current_url, href)
                            if is_valid_url(full_url, url) and full_url not in visited_urls:
                                url_queue.put(full_url)

                    # Track findings
                    scan_state['results']['pages'].append({
                        'url': current_url,
                        'status': response.status_code,
                        'title': soup.title.string if soup.title else 'No title'
                    })

                    if 'Index of' in response.text:
                        scan_state['results']['hidden_dirs'].append(current_url)

                    if current_url.endswith('.php'):
                        scan_state['results']['php_files'].append(current_url)

                except Exception as e:
                    logging.error(f"Error crawling {current_url}: {str(e)}")

                time.sleep(0.1)  # Rate limiting


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    url = data.get('url')
    options = data.get('options', {})

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    reset_scan_state()
    scan_state['is_scanning'] = True

    def run_scan():
        try:
            # Get network information first
            domain = urllib.parse.urlparse(url).netloc
            scan_state['results']['network_info'] = get_network_info(domain, options)

            if options.get('crawlPages', False):
                # Crawl pages
                crawl_site(url)

            if options.get('findDirs', False):
                # Directory bruteforce
                wordlist = options.get('wordlist')
                dirs = directory_bruteforce(url, wordlist)
                scan_state['results']['hidden_dirs'].extend(dirs)

            scan_state['is_scanning'] = False
            update_progress(100, 'Scan Complete')

        except Exception as e:
            logging.error(f"Scan error: {str(e)}")
            scan_state['is_scanning'] = False

    # Start scan in background thread
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

    return jsonify({'message': 'Scan started'})


@app.route('/start_network_scan', methods=['POST'])
def start_network_scan():
    data = request.json
    target = data.get('target')
    options = data.get('options', {})

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    reset_scan_state()
    scan_state['is_scanning'] = True

    def run_network_scan():
        try:
            scan_state['results']['network_info'] = get_network_info(target, options)

            if options.get('dirBuster', False):
                dirs = directory_bruteforce(f"http://{target}", options.get('wordlist'))
                scan_state['results']['hidden_dirs'].extend(dirs)

            scan_state['is_scanning'] = False
            update_progress(100, 'Network Scan Complete')

        except Exception as e:
            logging.error(f"Network scan error: {str(e)}")
            scan_state['is_scanning'] = False

    # Start scan in background thread
    thread = threading.Thread(target=run_network_scan)
    thread.daemon = True
    thread.start()

    return jsonify({'message': 'Network scan started'})


@app.route('/scan_status')
def scan_status():
    return jsonify({
        'is_complete': not scan_state['is_scanning'],
        'progress': scan_state['progress'],
        'current_task': scan_state['current_task'],
        'pages_found': len(scan_state['results']['pages']),
        'hidden_dirs': len(scan_state['results']['hidden_dirs']),
        'php_files': len(scan_state['results']['php_files']),
        'encoded_data': len(scan_state['results']['encoded_data']),
        'network_info': scan_state['results']['network_info'],
        'vulnerabilities': scan_state['results']['vulnerabilities']
    })


if __name__ == '__main__':
    app.run(debug=True)
