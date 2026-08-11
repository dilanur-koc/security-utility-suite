import random
import time
import requests

BASE_URL = "http://localhost:8080"
LOGIN_PAGE_URL = f"{BASE_URL}/login.html"
PERFORM_LOGIN_URL = f"{BASE_URL}/perform-login"
ANALYZE_URL = f"{BASE_URL}/api/v1/logs/analyze"

USERNAME = "admin"
PASSWORD = "Sifre123456"

# Gerçek Saldırı Payload'ları
SQLI_PAYLOADS = ["' OR '1'='1", "1 UNION SELECT null, pass FROM users--", "'; DROP TABLE logs;--"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "\"><img src=x onerror=alert(1)>"]

# Normal Yollar
NORMAL_PATHS = ["/index.html", "/products", "/about-us", "/contact", "/faq"]

# 🎯 Yalancı Çoban (Zararsız ama şüpheli kelimeler içeren istekler)
FALSE_POSITIVE_PATHS = [
    "/search?q=O'Neil",                         # Kesme işareti ' var ama isim
    "/forum?topic=how_to_use_script_tag",        # 'script' geçiyor ama konu başlığı
    "/calculator?expr=select_number_5_and_2",    # 'select' ve 'and' var ama hesaplama
    "/product?desc=100%25_pure_gold",            # Özel karakterli ürün araması
    "/articles?title=select_statement_in_sql"   # 'sql' kelimesi geçen blog başlığı
]

def run_stress_test_with_session(total_logs=1000):
    session = requests.Session()
    
    print("🔑 1. Oturum başlatılıyor...")
    try:
        login_page_res = session.get(LOGIN_PAGE_URL)
        xsrf_token = session.cookies.get("XSRF-TOKEN")
    except Exception as e:
        print(f"❌ Bağlantı hatası: {e}")
        return

    print("🔐 2. Giriş yapılıyor...")
    login_data = {"username": USERNAME, "password": PASSWORD}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if xsrf_token:
        headers["X-XSRF-TOKEN"] = xsrf_token

    login_res = session.post(PERFORM_LOGIN_URL, data=login_data, headers=headers)
    if login_res.status_code not in [200, 302]:
        print(f"⚠️ Giriş başarısız: {login_res.status_code}")
        return
        
    print("✅ Giriş Başarılı!\n")

    updated_xsrf = session.cookies.get("XSRF-TOKEN") or xsrf_token
    req_headers = {"Content-Type": "application/json"}
    if updated_xsrf:
        req_headers["X-XSRF-TOKEN"] = updated_xsrf

    print(f"🚀 {total_logs} adet log (saldırı + normal + yalancı çoban) üretiliyor...\n")
    
    logs_batch = []
    for _ in range(total_logs):
        ip = f"203.0.113.{random.randint(1, 254)}"
        timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0300")
        
        rand_val = random.random()
        if rand_val < 0.10:
            # %10 Gerçek Saldırı
            payload = random.choice(SQLI_PAYLOADS + XSS_PAYLOADS)
            path = f"/search?q={payload}"
            status = 403
        elif rand_val < 0.25:
            # %15 Yalancı Çoban (Zararsız Şüpheli)
            path = random.choice(FALSE_POSITIVE_PATHS)
            status = 200
        else:
            # %75 Normal Trafik
            path = random.choice(NORMAL_PATHS)
            status = 200
            
        logs_batch.append(f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} 1024')
    
    raw_log_payload = "\n".join(logs_batch)
    start_time = time.time()
    
    try:
        response = session.post(
            ANALYZE_URL,
            json={
                "logContent": raw_log_payload,
                "logSource": "AUTOMATED_STRESS_TEST"
            },
            headers=req_headers
        )
        
        elapsed_time = round(time.time() - start_time, 2)
        
        if response.status_code == 200:
            print("==================================================")
            print(f"🎉 TEST TAMAMLANDI! ({elapsed_time} saniyede)")
            print("==================================================")
            print(f"📊 Toplam İşlenen Log : {total_logs}")
            print(f"⚡ Status            : {response.status_code} OK")
            print("==================================================")
        else:
            print(f"⚠️ Hata: {response.status_code}")

    except Exception as e:
        print(f"❌ İstek hatası: {e}")

if __name__ == "__main__":
    run_stress_test_with_session(total_logs=1000)