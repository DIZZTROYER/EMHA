import argparse
import email
from email import policy
import dns.resolver
import re
import logging

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
    logging.info("\n===== Received Path (Newest to Oldest) =====")
    for hop in received:
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', hop) or re.search(r'\[([a-fA-F0-9:]+)\]', hop)
        time_match = re.search(r';\s*(.*)$', hop)
        ip = ip_match.group(1) if ip_match else 'Unknown'
        time = time_match.group(1) if time_match else 'Unknown'
        logging.info(f"Hop: {hop}")
        logging.info(f"  - IP: {ip}")
        logging.info(f"  - Time: {time}")
    if len(received) < 2:
        logging.warning("Warning: Short path - Possible direct injection or spoofing.")

def check_authentication(msg):
    from_domain = re.search(r'@([\w\.-]+)', msg['From']).group(1) if msg['From'] else None
    if not from_domain:
        logging.warning("No From domain - High spoofing risk.")
        return

    logging.info("\n===== Authentication Checks =====")
    
    # SPF
    try:
        received = msg.get_all('Received')
        sender_ip = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received[-1] if received else '').group(1)
        if sender_ip:
            spf_records = dns.resolver.resolve(from_domain, 'TXT')
            spf_result = 'Fail'
            for record in spf_records:
                txt = str(record).strip('"')
                if txt.startswith('v=spf1') and sender_ip in txt:
                    spf_result = 'Pass'
                    break
            logging.info(f"SPF: {spf_result} (Sender IP: {sender_ip})")
        else:
            logging.warning("SPF: Unknown - No sender IP.")
    except dns.resolver.NoAnswer:
        logging.warning("SPF: Fail - No record.")
    except Exception as e:
        logging.error(f"SPF Error: {e}")

    # DKIM
    dkim = msg['DKIM-Signature']
    if dkim:
        logging.info("DKIM: Present")
    else:
        logging.warning("DKIM: Missing")

    # DMARC
    try:
        dmarc_records = dns.resolver.resolve(f'_dmarc.{from_domain}', 'TXT')
        dmarc_result = 'None'
        for record in dmarc_records:
            txt = str(record).strip('"')
            if txt.startswith('v=DMARC1'):
                policy_match = re.search(r'p=([a-z]+)', txt)
                dmarc_result = policy_match.group(1).capitalize() if policy_match else 'None'
                break
        logging.info(f"DMARC Policy: {dmarc_result}")
    except dns.resolver.NoAnswer:
        logging.warning("DMARC: None - No record.")
    except Exception as e:
        logging.error(f"DMARC Error: {e}")

def flag_risks(msg):
    logging.info("\n=== Risk Flags ===")
    if msg['From'] != msg['Reply-To']:
        logging.warning("Spoofing Risk: From/Reply-To mismatch.")
    received = msg.get_all('Received') or []
    if len(received) < 3:
        logging.warning("Path Risk: Short chain - Forgery possible.")

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
        logging.error(f"Error parsing email: {e}")

if __name__ == "__main__":

    main()
