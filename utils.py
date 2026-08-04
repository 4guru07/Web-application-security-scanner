import re
import socket
from urllib.parse import urlparse
import validators

def validate_url(url_string):
    """
    Validates format and accessibility of the input URL.
    Returns (is_valid, normalized_url_or_error_message).
    """
    if not url_string:
        return False, "URL cannot be empty."

    url = url_string.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    if not validators.url(url):
        return False, "Invalid URL format. Please provide a valid HTTP/HTTPS URL."

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return False, "Invalid target hostname."

    # Prevent loopback/internal IP targeting for safety
    try:
        ip = socket.gethostbyname(hostname)
        if ip.startswith("127.") or ip == "0.0.0.0" or ip.startswith("169.254."):
            return False, "Scanning local loopback or link-local IP addresses is prohibited."
    except socket.gaierror:
        return False, f"Could not resolve domain name: {hostname}"

    return True, url

def extract_domain(url):
    """Extracts hostname from URL."""
    parsed = urlparse(url)
    return parsed.hostname or url
