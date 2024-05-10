from app import app, db, Scan
import pytest
import re
import requests
import warnings
from app import detect_injection, detect_sql_injection, detect_open_redirect, detect_ssrf, detect_xss, detect_csrf

@pytest.fixture(autouse=True)
def ignore_sqlalchemy_deprecations():
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        yield

@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()

    with app.app_context():
        db.create_all()
        yield client
        db.drop_all()

def test_save(client):
    # Test saving scan results
    response = client.post('/save', data={
        'url': 'https://blog.dinosec.com/2013/11/owasp-vulnerable-web-applications.html',
        'xss': 'Low',
        'csrf': 'Low',
        'injection': 'Low',
        'sql_injection': 'Low',
        'open_redirect': 'Low',
        'ssrf': 'Low'
    })

    assert response.status_code == 302

    with app.app_context():
        assert Scan.query.filter_by(url='https://blog.dinosec.com/2013/11/owasp-vulnerable-web-applications.html').first() is not None

def test_delete_scan(client):
    # Test deleting a scan
    with app.app_context():
        scan = Scan(url='https://blog.dinosec.com/2013/11/owasp-vulnerable-web-applications.html', xss_severity='Low', csrf_severity='Low',
                    injection_severity='Low', sql_injection_severity='Low', open_redirect_severity='Low',
                    ssrf_severity='Low')
        db.session.add(scan)
        db.session.commit()

    response = client.post('/delete/1')

    assert response.status_code == 302

    with app.app_context():
        session = db.session
        assert session.query(Scan).get(1) is None

def test_scan_route(client):
    # Test scanning a URL
    response = client.post('/scan', data={'url': 'https://blog.dinosec.com/2013/11/owasp-vulnerable-web-applications.html'})
    assert response.status_code == 200
    assert b'XSS Vulnerability Detected' in response.data

def test_detect_injection():
    result = detect_injection("https://blog.dinosec.com/2013/11/owasp-vulnerable-web-applications.html")
    assert result['severity'] == 'High'
    
def test_detect_sql_injection():
    result = detect_sql_injection("https://blog.dinosec.com/2013/11/owasp-vulnerable-web-applications.html")
    assert result['severity'] == 'High'

def test_detect_open_redirect():
    result = detect_open_redirect("https://blog.dinosec.com/2013/11/owasp-vulnerable-web-applications.html")
    assert result['severity'] == 'Low'

def test_detect_ssrf():
    result = detect_ssrf("https://blog.dinosec.com/2013/11/owasp-vulnerable-web-applications.html")
    assert result['severity'] == 'Low'

def test_detect_xss():
    result = detect_xss("https://blog.dinosec.com/2013/11/owasp-vulnerable-web-applications.html")
    assert result['severity'] == 'High'

def test_detect_csrf():
    result = detect_csrf("https://blog.dinosec.com/2013/11/owasp-vulnerable-web-applications.html")
    assert result['severity'] == 'Low'
