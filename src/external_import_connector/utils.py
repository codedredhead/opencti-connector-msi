#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
import re
import validators
import ipaddress

def extract_ips(links, config, helper):
    """
    Extract observable values from HTML links using configured regex patterns.
    Despite the name, this function handles all observable types: IPs, domains,
    URLs, emails, and file hashes - not just IP addresses.
    """
    entities=[]
    for link in links:
    # Extract IP from the link text
        link_text = link.get_text(strip=True)

        # Extract observable value using configured regex pattern
        # Supports IPv4, IPv6, domain names, URLs, email addresses, and file hashes
        if re.match(config.capture_regex, link_text):
            entity_data = {
                'raw_entry': str(link),
                'observable_value': link_text,
                'indicators': [link_text]
            }

            # Additional parsing if capture_regex is configured
            if hasattr(config, 'capture_regex') and config.capture_regex:
                try:
                    match_pattern = re.compile(config.capture_regex)
                    matches = match_pattern.findall(link_text)
                    if matches:
                        entity_data['indicators'] = matches
                        entity_data['observable_value'] = matches[0]
                except re.error as e:
                    helper.connector_logger.error(
                        f"[MSI] INVALID capture_regex pattern: '{config.capture_regex}' - {str(e)}"
                    )
                    raise

            entities.append(entity_data)
    return entities


def is_cidr_notation(value: str) -> bool:
    """
    Check if the value is in CIDR notation (e.g., 192.168.1.0/24)
    """
    try:
        ipaddress.ip_network(value, strict=False)
        return '/' in value
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_single_ip(value: str) -> bool:
    """
    Check if the value is a single IP address (IPv4 or IPv6)
    """
    try:
        ipaddress.ip_address(value)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def detect_ip_format(value: str) -> str:
    """
    Detect the format of an IP value
    Returns: 'single_ipv4', 'single_ipv6', 'cidr_ipv4', 'cidr_ipv6', 'unknown'
    """
    if is_cidr_notation(value):
        try:
            network = ipaddress.ip_network(value, strict=False)
            return f'cidr_ipv{network.version}'
        except:
            return 'unknown'
    elif is_single_ip(value):
        try:
            addr = ipaddress.ip_address(value)
            return f'single_ipv{addr.version}'
        except:
            return 'unknown'
    return 'unknown'


def extract_mixed_ips(links, config, helper):
    """
    Enhanced version of extract_ips that handles both individual IPs and CIDR notation
    """
    entities = []
    for link in links:
        link_text = link.get_text(strip=True)

        # Check if it matches the configured regex
        if re.match(config.capture_regex, link_text):
            # Determine IP format type
            ip_format = detect_ip_format(link_text)

            entity_data = {
                'raw_entry': str(link),
                'observable_value': link_text,
                'indicators': [link_text],
                'ip_format': ip_format  # Track format for STIX conversion
            }

            # Additional parsing if capture_regex is configured
            if hasattr(config, 'capture_regex') and config.capture_regex:
                try:
                    match_pattern = re.compile(config.capture_regex)
                    matches = match_pattern.findall(link_text)
                    if matches:
                        entity_data['indicators'] = matches
                        entity_data['observable_value'] = matches[0]
                        entity_data['ip_format'] = detect_ip_format(matches[0])
                except re.error as e:
                    helper.connector_logger.error(
                        f"[MSI] INVALID capture_regex pattern: '{config.capture_regex}' - {str(e)}"
                    )
                    raise

            entities.append(entity_data)

    return entities

def extract_urls_from_html(config, response):
    """Extract URLs from HTML response using regex pattern"""
    entities = []
    body_match = re.search(r'<body.*?>(.*?)<\/body>', response, re.S | re.I)
    if body_match:
        body_content = body_match.group(1)
    else:
        body_content = response  # fallback if <body> not found

    # Remove <script>...</script> blocks
    body_no_scripts = re.sub(r'<script.*?>.*?<\/script>', '', body_content, flags=re.S | re.I)

    # Find all URLs using capture_regex
    pattern = re.compile(config.capture_regex, re.I)
    urls = pattern.findall(body_no_scripts)

    # Dedupe and validate URLs
    unique_urls = set(urls)
    for url in unique_urls:
        # Additional validation using validators library
        if validators.url(url):
            entity_data = {
                'raw_entry': str(url),
                'observable_value': url,
                'indicators': [url]
            }
            entities.append(entity_data)

    return entities

def extract_domains_from_html(config,response):
    entities=[]
    body_match = re.search(r'<body.*?>(.*?)<\/body>', response, re.S | re.I)
    if body_match:
        body_content = body_match.group(1)
    else:
        body_content = response  # fallback if <body> not found

    # Remove <script>...</script> blocks
    body_no_scripts = re.sub(r'<script.*?>.*?<\/script>', '', body_content, flags=re.S | re.I)

    # Find all domains
    pattern = re.compile(config.capture_regex, re.I)
    domains = pattern.findall(body_no_scripts)

    # Deduplicate
    unique_domains = set(domains)
    for domain in unique_domains:
        entity_data = {
            'raw_entry': str(domain),
            'observable_value': domain,
            'indicators': [domain]
            }
        entities.append(entity_data)

    return entities


def calculate_response_metrics(response):
    """
    Calculate response size metrics for HTTP responses.

    Args:
        response: requests.Response object

    Returns:
        dict: Dictionary containing response size metrics
    """
    content_length = len(response.content) if response.content else 0
    response_headers_size = sum(len(f"{k}: {v}") for k, v in response.headers.items())
    total_response_size = content_length + response_headers_size

    return {
        "content_length_bytes": content_length,
        "headers_size_bytes": response_headers_size,
        "total_response_size_bytes": total_response_size,
        "content_type": response.headers.get('content-type', 'unknown'),
        "status_code": response.status_code
    }
