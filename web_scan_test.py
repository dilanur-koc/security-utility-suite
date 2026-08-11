import time
import requests

BASE_URL = "http://localhost:8080"
LOGIN_PAGE_URL = f"{BASE_URL}/login.html"
PERFORM_LOGIN_URL = f"{BASE_URL}/perform-login"
SCANNER_URL = f"{BASE_URL}/api/v1/scanner/scan"

USERNAME = "admin"
PASSWORD = "Sifre123456"

TEST_TARGETS = [
    {"targetUrl": "https://example.com/search?q=<svg onload=alert(document.domain)>", "scanXss": True, "scanSqli": False},
    {"targetUrl": "https://example.com/user?id=1' AND 1=2 UNION ALL SELECT 1, @@version--", "scanXss": False, "scanSqli": True},
    {"targetUrl": "https://example.com/comment?text=javascript:alert(document.cookie)", "scanXss": True, "scanSqli": True}
]

def run_web_scanner_test():
    session = requests.Session()
    print("🔑 1. Oturum açılıyor...")
    try:
        login_page_res = session.get(LOGIN_PAGE_URL)
        xsrf_token = session.cookies.get("XSRF-TOKEN")
    except Exception as e:
        print(f"❌ Bağlantı hatası: {e}")
        return

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if xsrf_token:
        headers["X-XSRF-TOKEN"] = xsrf_token

    login_res = session.post(PERFORM_LOGIN_URL, data={"username": USERNAME, "password": PASSWORD}, headers=headers)
    if login_res.status_code not in [200, 302]:
        print(f"⚠️ Giriş Başarısız: {login_res.status_code}")
        return
        
    print("✅ Giriş Başarılı!\n")

    updated_xsrf = session.cookies.get("XSRF-TOKEN") or xsrf_token
    req_headers = {"Content-Type": "application/json"}
    if updated_xsrf:
        req_headers["X-XSRF-TOKEN"] = updated_xsrf

    print("🚀 Web Zafiyet Tarama istekleri gönderiliyor...\n")
    for idx, target in enumerate(TEST_TARGETS, 1):
        print(f"🔍 [{idx}/{len(TEST_TARGETS)}] Hedef: {target['targetUrl']}")
        try:
            res = session.post(SCANNER_URL, json=target, headers=req_headers)
            print(f"   ⚡ Status: {res.status_code} OK")
        except Exception as e:
            print(f"   ❌ Hata: {e}")

if __name__ == "__main__":
    run_web_scanner_test()
