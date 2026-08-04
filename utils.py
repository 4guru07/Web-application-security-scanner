import re
import socket
from urllib.parse import urlparse
import validators

def validate_url(input_string):
    """
    Validates input string (URL, domain name, or IP address).
    Resolves target IPv4 address and target hostname.
    Returns (is_valid, normalized_url, ip_address, target_name_or_error).
    """
    if not input_string:
        return False, None, None, "Input target cannot be empty."

    raw_input = input_string.strip()
    
    # Check if input is a raw IPv4 address
    ip_pattern = r'^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    is_ip = bool(re.match(ip_pattern, raw_input))

    if is_ip:
        ip_address = raw_input
        # Block private/loopback IPs
        if ip_address.startswith("127.") or ip_address == "0.0.0.0" or ip_address.startswith("169.254.") or ip_address.startswith("10.") or ip_address.startswith("192.168."):
            return False, None, None, "Scanning local loopback or private internal IP addresses is prohibited."
        
        normalized_url = f"http://{ip_address}"
        try:
            target_name = socket.gethostbyaddr(ip_address)[0]
        except Exception:
            target_name = f"IP: {ip_address}"
        
        return True, normalized_url, ip_address, target_name

    # If domain/URL input
    url = raw_input
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return False, None, None, "Invalid target domain or hostname."

    # Validate hostname syntax or URL syntax
    if not validators.url(url) and not validators.domain(hostname):
        return False, None, None, "Invalid URL, Domain, or IP address format."

    # Resolve IP address via DNS lookup
    try:
        ip_address = socket.gethostbyname(hostname)
        if ip_address.startswith("127.") or ip_address == "0.0.0.0" or ip_address.startswith("169.254."):
            return False, None, None, "Scanning local loopback or link-local IP addresses is prohibited."
    except socket.gaierror:
        # Retry with HTTP protocol scheme if HTTPS DNS resolution failed
        try:
            ip_address = socket.gethostbyname(hostname.replace('https://', '').replace('http://', ''))
        except Exception:
            return False, None, None, f"Could not resolve domain IP for: {hostname}"

    target_name = hostname
    return True, url, ip_address, target_name

def extract_domain(url):
    """Extracts hostname from URL."""
    parsed = urlparse(url)
    return parsed.hostname or url
