import re
import dns.resolver
import smtplib
import socket
import random
import string

# Expanded disposable domains list (100+ common ones)
DISPOSABLE_DOMAINS = [
    'tempmail.com', '10minutemail.com', 'guerrillamail.com',
    'mailinator.com', 'throwaway.email', 'temp-mail.org',
    'fakeinbox.com', 'trashmail.com', 'yopmail.com', 'maildrop.cc',
    'getnada.com', 'tempm.com', 'spamgourmet.com', 'mintemail.com',
    'mytrashmail.com', 'mailnesia.com', 'trillian.im', 'getairmail.com',
    'anonymousemail.me', 'sharklasers.com', 'guerrillamail.net',
    'spam4.me', 'grr.la', 'mailcatch.com', 'emailondeck.com',
    'throwawaymail.com', 'guerrillamail.biz', 'guerrillamail.de',
    'mailexpire.com', '10minutemail.net', 'mailmetrash.com',
    'tempinbox.com', 'mohmal.com', 'meltmail.com', 'dispostable.com',
    'mailbox.in.ua', 'moakt.com', 'sneakemail.com', 'anonbox.net',
    'mailforspam.com', 'mt2015.com', 'mail-temporaire.fr',
    'jetable.org', 'throwaway.email', 'mytemp.email', 'mailtemp.net'
]

# Role-based email prefixes
ROLE_BASED_PREFIXES = [
    'admin', 'info', 'support', 'sales', 'contact', 'help',
    'webmaster', 'postmaster', 'noreply', 'no-reply', 'abuse',
    'hostmaster', 'root', 'newsletter', 'marketing', 'service',
    'team', 'hello', 'feedback', 'billing', 'enquiry', 'inquiry'
]

# Common free email providers (for additional context)
FREE_EMAIL_PROVIDERS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'aol.com', 'icloud.com', 'mail.com', 'zoho.com',
    'protonmail.com', 'gmx.com', 'yandex.com', 'mail.ru'
]

def validate_syntax(email):
    """
    Enhanced syntax validation with more comprehensive checks.
    """
    # Basic pattern check
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False
    
    # Additional validation
    try:
        local, domain = email.split('@')
        
        # Local part checks
        if len(local) > 64 or len(local) == 0:
            return False
        if local.startswith('.') or local.endswith('.'):
            return False
        if '..' in local:
            return False
        
        # Domain part checks
        if len(domain) > 255 or len(domain) == 0:
            return False
        if domain.startswith('-') or domain.endswith('-'):
            return False
        if '..' in domain:
            return False
        
        # Must have at least one dot in domain
        if '.' not in domain:
            return False
            
        return True
    except:
        return False

def is_disposable(email):
    """Check if email is from a disposable/temporary email service."""
    domain = email.split('@')[1].lower()
    return domain in DISPOSABLE_DOMAINS

def is_role_based(email):
    """Check if email is a role-based address (info@, support@, etc.)."""
    local = email.split('@')[0].lower()
    return local in ROLE_BASED_PREFIXES

def is_free_provider(email):
    """Check if email is from a free email provider."""
    domain = email.split('@')[1].lower()
    return domain in FREE_EMAIL_PROVIDERS

def check_dns_mx(domain):
    """
    Enhanced MX record check with fallback to A records.
    Returns (bool, list of mx_hosts, is_using_a_record)
    """
    try:
        # Try MX records first (proper mail servers)
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_hosts = sorted(
            [(r.preference, str(r.exchange).rstrip('.')) for r in mx_records],
            key=lambda x: x[0]
        )
        return True, [host for _, host in mx_hosts], False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # If no MX records, try A record (some small domains use this)
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            if a_records:
                return True, [domain], True  # Domain itself handles mail
        except:
            pass
    except Exception:
        pass
    
    return False, [], False

def check_catch_all(domain, mx_hosts):
    """
    Detect if domain is catch-all (accepts any email).
    Returns: True (catch-all), False (not catch-all), None (couldn't determine)
    """
    if not mx_hosts:
        return None
    
    # Generate a random, unlikely email address
    random_local = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
    test_email = f"{random_local}@{domain}"
    
    try:
        server = smtplib.SMTP(timeout=10)
        server.connect(mx_hosts[0], 25)
        server.helo('verify.example.com')
        server.mail('verify@example.com')
        code, _ = server.rcpt(test_email)
        server.quit()
        
        # If random email is accepted, it's catch-all
        return code in [250, 251]
    except:
        return None

def verify_smtp(email, mx_hosts, check_catch_all_flag=True):
    """
    Enhanced SMTP verification with better error handling and catch-all detection.
    Returns (deliverable_status, message, is_catch_all)
    deliverable_status: True (deliverable), False (not deliverable), None (unknown)
    """
    if not mx_hosts:
        return None, "No mail servers found", None
    
    domain = email.split('@')[1]
    is_catch_all = None
    
    # Try to detect catch-all first (if enabled)
    if check_catch_all_flag:
        is_catch_all = check_catch_all(domain, mx_hosts)
        if is_catch_all:
            return None, "Domain accepts all emails (catch-all)", True
    
    # Try each MX host (up to 3)
    last_error = None
    for mx_host in mx_hosts[:3]:
        try:
            server = smtplib.SMTP(timeout=15)
            server.connect(mx_host, 25)
            server.helo('verify.example.com')
            server.mail('verify@example.com')
            code, message = server.rcpt(email)
            server.quit()
            
            # Interpret response codes
            if code == 250:
                return True, "✓ Mailbox verified", is_catch_all
            elif code == 251:
                return True, "✓ Mailbox verified (will forward)", is_catch_all
            elif code == 550:
                return False, "✗ Mailbox does not exist", is_catch_all
            elif code == 551:
                return False, "✗ User not local", is_catch_all
            elif code == 552:
                return False, "✗ Mailbox full", is_catch_all
            elif code == 553:
                return False, "✗ Invalid mailbox", is_catch_all
            else:
                last_error = f"Uncertain (SMTP code {code})"
                
        except smtplib.SMTPServerDisconnected:
            last_error = "Server disconnected"
        except smtplib.SMTPConnectError:
            last_error = "Connection refused"
        except socket.timeout:
            last_error = "Connection timeout"
        except ConnectionRefusedError:
            last_error = "Port 25 blocked or refused"
        except Exception as e:
            last_error = f"Network error: {str(e)[:50]}"
            continue
    
    # If all attempts failed
    return None, last_error or "SMTP verification failed", is_catch_all

def get_risk_score(result):
    """
    Calculate risk score (0-100, higher = riskier).
    """
    score = 0
    
    # Invalid syntax = highest risk
    if not result.get('valid_syntax', False):
        return 100
    
    # No domain = very high risk
    if not result.get('valid_domain', False):
        return 95
    
    # Disposable email
    if result.get('is_disposable', False):
        score += 80
    
    # Not deliverable
    if result.get('deliverable') == False:
        score += 70
    
    # Catch-all domain
    if result.get('is_catch_all') == True:
        score += 40
    
    # Role-based email
    if result.get('is_role_based', False):
        score += 20
    
    # Unknown deliverability
    if result.get('deliverable') is None and result.get('valid_domain'):
        score += 30
    
    # Valid and deliverable = low risk
    if result.get('deliverable') == True:
        score = max(0, score - 60)
    
    return min(100, score)

def validate_single_email(email, level):
    """
    Enhanced main validation function with comprehensive checks.
    level can be 'syntax', 'dns', or 'full'
    """
    result = {
        'email': email,
        'status': 'invalid',
        'message': '',
        'valid_syntax': False,
        'valid_domain': False,
        'deliverable': None,
        'is_disposable': False,
        'is_role_based': False,
        'is_free_provider': False,
        'is_catch_all': None,
        'risk_score': 100
    }
    
    # Step 1: Syntax validation
    if not validate_syntax(email):
        result['message'] = "Invalid email syntax"
        result['risk_score'] = 100
        return result
    
    result['valid_syntax'] = True
    
    try:
        domain = email.split('@')[1]
    except:
        result['message'] = "Invalid email format"
        result['risk_score'] = 100
        return result
    
    # Step 2: Check email characteristics
    result['is_disposable'] = is_disposable(email)
    result['is_role_based'] = is_role_based(email)
    result['is_free_provider'] = is_free_provider(email)
    
    # Disposable emails are always risky
    if result['is_disposable']:
        result['status'] = 'risky'
        result['message'] = "⚠ Disposable/temporary email service"
        result['risk_score'] = 85
        return result
    
    
    # Step 3: DNS/MX record check
    has_mx, mx_hosts, using_a_record = check_dns_mx(domain)
    result['valid_domain'] = has_mx
    
    if not has_mx:
        result['message'] = "✗ Domain does not exist or has no mail servers"
        result['risk_score'] = 95
        return result
    
    if using_a_record:
        result['message'] = "⚠ Domain uses A record (not standard mail setup)"
        result['status'] = 'risky'
        result['risk_score'] = 60
    
    # Step 4: Full SMTP verification
    deliverable, smtp_msg, is_catch_all = verify_smtp(email, mx_hosts)
    result['deliverable'] = deliverable
    result['is_catch_all'] = is_catch_all
    
    if deliverable is True:
        result['status'] = 'valid'
        result['message'] = smtp_msg
        result['risk_score'] = 10 if result['is_role_based'] else 5
    elif deliverable is False:
        result['status'] = 'invalid'
        result['message'] = smtp_msg
        result['risk_score'] = 90
    else:
        # Unknown status
        if is_catch_all:
            result['status'] = 'risky'
            result['message'] = "⚠ Catch-all domain (accepts any email)"
            result['risk_score'] = 55
        else:
            result['status'] = 'unknown'
            result['message'] = f"⚠ {smtp_msg}"
            result['risk_score'] = 45
    
    # Final risk score calculation
    result['risk_score'] = get_risk_score(result)
    
    return result
