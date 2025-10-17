import json
import re
from flask import Flask, render_template, request, jsonify
from threading import Thread
from concurrent.futures import ThreadPoolExecutor

from validator import validate_single_email # Import the core logic

app = Flask(__name__)

# --- Configuration ---
# Setting max workers for ThreadPoolExecutor based on common low-end CPU core count
MAX_WORKERS = 4 

def validate_bulk(emails, level):
    """
    Validates a list of emails using a ThreadPoolExecutor for concurrency.
    """
    total_results = []
    
    # Use ThreadPoolExecutor for concurrent validation (especially for DNS/SMTP checks)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit tasks
        future_to_email = {executor.submit(validate_single_email, email.strip().lower(), level): email for email in emails if email.strip()}
        
        # Collect results as they complete
        for future in future_to_email:
            try:
                result = future.result()
                total_results.append(result)
            except Exception as exc:
                print(f'{future_to_email[future]} generated an exception: {exc}')
                total_results.append({
                    'email': future_to_email[future],
                    'status': 'error',
                    'message': 'Server processing error'
                })
    return total_results

@app.route('/')
def index():
    """Renders the main page."""
    return render_template('index.html')

@app.route('/validate', methods=['POST'])
def validate_endpoint():
    """API endpoint to handle email validation requests."""
    data = request.json
    
    if not data or 'emails' not in data:
        return jsonify({"error": "Invalid request payload"}), 400

    raw_emails = data['emails']
    level = 'full'
    
    # Split by newlines, commas, semicolons, then filter out empty strings
    emails = []
    for line in raw_emails.split('\n'):
        emails.extend(re.split(r'[,;]', line))
    
    # Simple regex to filter non-email-looking strings before validation
    emails = [e.strip() for e in emails if e.strip() and '@' in e]

    if not emails:
        return jsonify({"error": "No valid emails provided for validation"}), 400

    # Execute validation in bulk
    validation_results = validate_bulk(emails, level)
    
    # Calculate statistics for the results header
    stats = {
        'total': len(validation_results),
        'valid': sum(1 for r in validation_results if r['status'] == 'valid'),
        'invalid': sum(1 for r in validation_results if r['status'] == 'invalid'),
        'risky': sum(1 for r in validation_results if r['status'] == 'risky'),
        'unknown': sum(1 for r in validation_results if r['status'] == 'unknown')
    }

    return jsonify({"results": validation_results, "stats": stats})

if __name__ == '__main__':
    # For local development, you can still run this file.
    # The production server will be started by Gunicorn as specified in render.yaml.
    app.run()
