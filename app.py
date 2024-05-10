from flask import Flask, render_template, request, redirect, url_for
import requests
import re
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret_key'

db = SQLAlchemy(app)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    xss_severity = db.Column(db.String(50))
    xss_comment = db.Column(db.String(200))
    xss_action = db.Column(db.String(200))
    csrf_severity = db.Column(db.String(50))
    csrf_comment = db.Column(db.String(200))
    csrf_action = db.Column(db.String(200))
    injection_severity = db.Column(db.String(50))
    injection_comment = db.Column(db.String(200))
    injection_action = db.Column(db.String(200))
    sql_injection_severity = db.Column(db.String(50))
    sql_injection_comment = db.Column(db.String(200))
    sql_injection_action = db.Column(db.String(200))
    open_redirect_severity = db.Column(db.String(50))
    open_redirect_comment = db.Column(db.String(200))
    open_redirect_action = db.Column(db.String(200))
    ssrf_severity = db.Column(db.String(50))
    ssrf_comment = db.Column(db.String(200))
    ssrf_action = db.Column(db.String(200))
    
#saving button if the user would like to keep the recent scan in the database.
@app.route('/save', methods=['POST'])
def save():
    url = request.form.get('url')
    results = {
        'xss': request.form.get('xss'),
        'csrf': request.form.get('csrf'),
        'injection': request.form.get('injection'),
        'sql_injection': request.form.get('sql_injection'),
        'open_redirect': request.form.get('open_redirect'),
        'ssrf': request.form.get('ssrf')
    }
    scan_data = Scan(
        url=url,
        xss_severity=results['xss'],
        csrf_severity=results['csrf'],
        injection_severity=results['injection'],
        sql_injection_severity=results['sql_injection'],
        open_redirect_severity=results['open_redirect'],
        ssrf_severity=results['ssrf']
    )
    with app.app_context():
        db.session.add(scan_data)
        db.session.commit()
    return redirect(url_for('index'))

#delete function button for the recent scans.
@app.route('/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/')
def index():
    saved_scans = Scan.query.all()
    return render_template('index.html', saved_scans=saved_scans)

#these are the 6 vulnerabilities that will be detected from each website.
def detect_xss(url):
    response = requests.get(url)
    if "<script>" in response.text:
        return {
            'severity': 'High',
            'comment': 'XSS Vulnerability Detected. This can allow attackers to execute malicious scripts in the user\'s browser.',
            'action': 'Clean the user inputs and use Content Security Policy (CSP) to mitigate XSS attacks.'
        }
    return {
        'severity': 'Low',
        'comment': 'No XSS Vulnerability Detected.',
        'action': 'There is no detection of this vulnerability.'
    }


def detect_csrf(url):
    response = requests.get(url)
    if "csrf_token" in response.text:
        return {
            'severity': 'Medium',
            'comment': 'CSRF Vulnerability Detected. This can allow attackers to perform actions on behalf of the user.',
            'action': 'Apply anti-CSRF tokens and ensure secure state-changing operations.'
        }
    return {
        'severity': 'Low',
        'comment': 'No CSRF Vulnerability Detected.',
        'action': 'There is no detection of this vulnerability.'
    }


def detect_injection(url):
    payload = "' OR '1'='1"
    response = requests.get(url + "?id=" + payload)
    if "Error" in response.text:
        return {
            'severity': 'High',
            'comment': 'Injection Vulnerability Detected. This can allow attackers to execute arbitrary commands or queries.',
            'action': 'Use parameterized queries and input validation to prevent injection attacks.'
        }
    return {
        'severity': 'Low',
        'comment': 'No Injection Vulnerability Detected.',
        'action': 'There is no detection of this vulnerability.'
    }


def detect_sql_injection(url):
    payload = "1' OR '1'='1"
    response = requests.get(url + "?id=" + payload)
    if "Error" in response.text:
        return {
            'severity': 'High',
            'comment': 'SQL Injection Vulnerability Detected. This can allow attackers to execute arbitrary SQL queries.',
            'action': 'Use parameterized queries and input validation to stop SQL injection.'
        }
    return {
        'severity': 'Low',
        'comment': 'No SQL Injection Vulnerability Detected.',
        'action': 'There is no detection of this vulnerability.'
    }


def detect_open_redirect(url):
    response = requests.get(url)
    redirect_pattern = re.compile(r"window\.location\.replace\('(.*?)'\);")
    redirect_urls = redirect_pattern.findall(response.text)
    if redirect_urls:
        return {
            'severity': 'Medium',
            'comment': f"Open Redirect Vulnerability Detected: Redirects to {redirect_urls[0]}. This can be used in phishing attacks.",
            'action': 'Stay away from using user-controlled input in redirect URLs.'
        }
    return {
        'severity': 'Low',
        'comment': 'No Open Redirect Vulnerability Detected.',
        'action': 'There is no detection of this vulnerability.'
    }


def detect_ssrf(url):
    payload = "http://localhost:5000/endpoint"
    response = requests.get(url + "?url=" + payload)
    if "localhost" in response.text:
        return {
            'severity': 'High',
            'comment': 'Server-Side Request Forgery (SSRF) Vulnerability Detected. This can allow attackers to access internal resources.',
            'action': 'Validate and sanitize user-supplied URLs and use allow-lists for safe domains.'
        }
    return {
        'severity': 'Low',
        'comment': 'No Server-Side Request Forgery (SSRF) Vulnerability Detected.',
        'action': 'There is no detection of this vulnerability.'
    }

#detection from the scans.
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    results = {
        'xss': detect_xss(url),
        'csrf': detect_csrf(url),
        'injection': detect_injection(url),
        'sql_injection': detect_sql_injection(url),
        'open_redirect': detect_open_redirect(url),
        'ssrf': detect_ssrf(url)
    }
    return render_template('result.html', results=results, url=url)


@app.route('/results')
def results():
    scans = Scan.query.all()
    return render_template('results.html', scans=scans)

@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)