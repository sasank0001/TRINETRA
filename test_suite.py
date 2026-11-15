import json
from app import app
from database import init_db, clear_history

init_db()
clear_history()

with app.test_client() as client:
    # 1. Test Home
    res = client.get('/')
    assert res.status_code == 200, f'Home failed: {res.status_code}'
    print('[+] Home page (200 OK)')

    # 2. Test Scanner Page
    res = client.get('/scanner')
    assert res.status_code == 200, f'Scanner page failed: {res.status_code}'
    print('[+] Scanner page (200 OK)')

    # 3. Test API Scan - Legitimate URL
    res = client.post('/api/scan', json={'url': 'https://www.google.com'})
    data = json.loads(res.data)
    assert res.status_code == 200 and data['success'], f'Scan legit failed: {data}'
    risk_level = data['data']['risk_level']
    risk_score = data['data']['risk_score']
    assert risk_level == 'LOW', f'Expected LOW, got {risk_level}'
    print(f'[+] Scan Legit (Google): {risk_level} ({risk_score}/100)')

    # 4. Test API Scan - Phishing URL
    res = client.post('/api/scan', json={'url': 'http://paypal-security-verification.update-auth.xyz/login.php'})
    data = json.loads(res.data)
    assert res.status_code == 200 and data['success'], f'Scan phish failed: {data}'
    phish_risk = data['data']['risk_level']
    phish_score = data['data']['risk_score']
    assert phish_risk == 'HIGH', f'Expected HIGH, got {phish_risk}'
    print(f'[+] Scan Phishing (PayPal fake): {phish_risk} ({phish_score}/100)')

    # 5. Test Dashboard
    res = client.get('/dashboard')
    assert res.status_code == 200, f'Dashboard failed: {res.status_code}'
    print('[+] Dashboard page (200 OK)')

    # 6. Test History Page
    res = client.get('/history')
    assert res.status_code == 200, f'History page failed: {res.status_code}'
    assert b'paypal-security-verification' in res.data, 'History table did not render scanned URL'
    print('[+] History page (200 OK - scanned records visible)')

    # 7. Test About Page
    res = client.get('/about')
    assert res.status_code == 200, f'About page failed: {res.status_code}'
    assert b'Developed by CSE and IT Students' in res.data
    print('[+] About page (200 OK - Student credits verified)')

    # 8. Test Input Validation
    res = client.post('/api/scan', json={'url': 'javascript:alert(1)'})
    assert res.status_code == 422, 'Did not reject javascript: URI'
    print('[+] Input validation: Successfully rejected malicious URI scheme (422)')
    print('\n[***] ALL 8 SYSTEM TESTS PASSED SUCCESSFULLY! [***]')
