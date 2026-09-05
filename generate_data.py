import csv
import os
import random
from datetime import datetime, timedelta

os.makedirs('data', exist_ok=True)

ips = ['192.168.1.10', '10.0.0.15', '172.16.0.4', '45.33.32.156', '185.220.101.5']
urls_clean = ['/home', '/login', '/dashboard', '/api/v1/profile', '/contact']
urls_sqli = [
    "/login?user=admin'--",
    "/api/v1/products?id=1%20OR%201=1",
    "/search?q=UNION%20SELECT%20username,password%20FROM%20users"
]

rows = []
base_time = datetime.now() - timedelta(hours=2)

# Trafic légitime
for i in range(200):
    timestamp = (base_time + timedelta(seconds=i*3)).strftime('%Y-%m-%d %H:%M:%S')
    ip = random.choice(ips[:3])
    url = random.choice(urls_clean)
    status = 200 if url != '/login' else random.choice([200, 401])
    rows.append([timestamp, ip, 'GET', url, status])

# Attaque Brute Force (IP 185.220.101.5)
for i in range(15):
    timestamp = (base_time + timedelta(seconds=300 + i)).strftime('%Y-%m-%d %H:%M:%S')
    rows.append([timestamp, '185.220.101.5', 'POST', '/login', 401])

# Attaques SQLi (IP 45.33.32.156)
for i, sqli_url in enumerate(urls_sqli):
    timestamp = (base_time + timedelta(seconds=400 + i*10)).strftime('%Y-%m-%d %H:%M:%S')
    rows.append([timestamp, '45.33.32.156', 'GET', sqli_url, 500])

with open('data/access_logs.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['timestamp', 'ip_address', 'method', 'url', 'status_code'])
    writer.writerows(rows)

print("✅ Fichier 'data/access_logs.csv' généré avec succès !")
