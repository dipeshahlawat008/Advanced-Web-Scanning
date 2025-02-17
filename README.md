# Advanced Web Scanner

A powerful web application security scanner that combines URL crawling, network reconnaissance, and vulnerability assessment capabilities in a modern web interface.

![Advanced Web Scanner Interface](screenshot.png)

## Features

### URL Scanning
- 🕷️ **Web Crawling**: Recursively crawl websites to discover all accessible pages
- 📁 **Directory Enumeration**: Detect hidden directories and sensitive paths
- 📜 **PHP File Detection**: Identify PHP files for potential vulnerabilities
- 🔍 **Encoded Data Detection**: Find and decode base64 and other encoded strings

### Network Scanning
- 🌐 **DNS Enumeration**: Comprehensive DNS record analysis (A, MX, NS, TXT, CNAME, SOA)
- 🔒 **SSL Certificate Analysis**: Examine SSL certificates for security issues
- 🚪 **Port Scanning**: Detect open ports and running services
- 📡 **Subnet Scanning**: Discover active hosts in the target's subnet

### Advanced Features
- 📊 **Real-time Progress Tracking**: Monitor scan progress with a dynamic interface
- 📝 **Custom Wordlists**: Support for custom directory bruteforce wordlists
- 🎯 **Targeted Scanning**: Choose specific scan components to run
- 🔄 **Concurrent Scanning**: Multi-threaded scanning for improved performance

## Installation
 pip install -r requirements.txt

## Requirements

- Python 3.9+
- Flask
- BeautifulSoup4
- python-nmap
- python-whois
- dnspython
- Additional requirements in `requirements.txt`

## Security Notice

⚠️ This tool is for security research and authorized testing only. Always obtain proper permission before scanning any systems you don't own.
