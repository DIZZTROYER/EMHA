import argparse
import email
from email import policy
import dns.resolver
import re
import logging
import ipaddress
import spf
import dkim


logging.basicConfig(level=logging.INFO, format='%(message)s')

def extract_basic_headers(msg):
    headers = {
        'From': msg['From'],
        'To': msg['To'],
        'Subject': msg['Subject'],
        'Date': msg['Date'],
        'Message-ID': msg['Message-ID'],
        'Reply-To': msg['Reply-To'],
        'X-Mailer': msg['X-Mailer']
    }
    logging.info("=== Basic Headers ===")
    for key, value in headers.items():
        logging.info(f"{key}: {value or 'Not Present'}")

def trace_path(msg):
    received = msg.get_all('Received') or []
    logging.info("\n=== Received Path (Newest to Oldest) ===")
    for hop in received:
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', hop)
        time_match = re.search(r';\s*(.*)$', hop)
        ip = ip_match.group(1) if ip_match else 'Unknown'
        time = time_match.group(1) if time_match else 'Unknown'
        logging.info(f"Hop: {hop}")
        logging.info(f"  - IP: {ip}")
        logging.info(f"  - Time: {time}")
    if len(received) < 2:
        logging.warning("Warning: Short path - Possible forgery.")

def find_originating_ip(received):
    for header in reversed(received):
        ips = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
        for ip in ips:
            if ipaddress.ip_address(ip).is_global:
                return ip
    return None

def check_authentication(msg):
    from_domain = re.search(r'@([\w\.-]+)', msg['From']).group(1) if msg['From'] else None
    if not from_domain:
        logging.warning("No From domain - High spoofing risk.")
        return

    logging.info("\n===== Authentication Checks =====")
    # SPF
    origin_ip = find_originating_ip(msg.get_all('Received') or [])
    envelope_from = msg['Return-Path'] or msg['From']
    helo = re.search(r'from\s+([^(\s]+)', msg.get_all('Received')[-1] if msg.get_all('Received') else '').group(1) if msg.get_all('Received') else None
    if origin_ip:
        result, detail = spf.check2(i=origin_ip, s=envelope_from, h=helo or '')
        logging.info(f"SPF: {result} (Detail: {detail.get('explanation', 'N/A')})")
    else:
        logging.warning("SPF: Unknown - No origin IP.")

    # DKIM
    dkim_ok, dkim_meta = dkim.verify(msg.as_bytes())
    logging.info(f"DKIM: {'Verified' if dkim_ok else 'Failed'} {dkim_meta or ''}")

    # DMARC
    try:
        dmarc_records = dns.resolver.resolve(f'_dmarc.{from_domain}', 'TXT')
        for record in dmarc_records:
            txt = str(record).strip('"')
            if txt.startswith('v=DMARC1'):
                policy = re.search(r'p=([a-z]+)', txt).group(1).capitalize()
                logging.info(f"DMARC Policy: {policy}")
                break
        else:
            logging.warning("DMARC: None")
    except dns.resolver.NoAnswer:
        logging.warning("DMARC: None")

def flag_risks(msg):
    logging.info("\n===== Risk Flags =====")
    if msg['From'] != msg['Reply-To']:
        logging.warning("Spoofing Risk: From/Reply-To mismatch.")
    if len(msg.get_all('Received') or []) < 3:
        logging.warning("Path Risk: Short chain.")

def main():
    parser = argparse.ArgumentParser(description="EMHA X.0: Email Header Analyzer")
    parser.add_argument('--eml', required=True, help="Path to .eml file")
    args = parser.parse_args()

    try:
        with open(args.eml, 'rb') as f:
            msg = email.message_from_bytes(f.read(), policy=policy.default)
        extract_basic_headers(msg)
        trace_path(msg)
        check_authentication(msg)
        flag_risks(msg)
    except FileNotFoundError:
        logging.error("Error: .eml file not found.")
    except Exception as e:
        logging.error(f"Error: {e}")

if __name__ == "__main__":
    main()
