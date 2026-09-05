import json
from pathlib import Path
import pandas as pd


def analyze_logs():
  try:
    # Détermination du chemin absolu du fichier access_logs.csv
    base_dir = Path(__file__).resolve().parent.parent
    csv_path = base_dir / 'data' / 'access_logs.csv'

    df = pd.read_csv(csv_path)

    # Conversion de la colonne status_code
    df['status_code'] = pd.to_numeric(df['status_code'], errors='coerce')

    # 1. Détection Brute Force (IPs avec > 5 échecs HTTP 401)
    failed_logins = df[df['status_code'] == 401]
    bf_attempts = failed_logins.groupby('ip_address').size()
    suspicious_ips = bf_attempts[bf_attempts > 5].index.tolist()

    # 2. Détection SQL Injection
    sqli_keywords = ['UNION', 'SELECT', 'OR 1=1', '--', 'DROP']
    pattern = '|'.join(sqli_keywords)
    sqli_matches = df[df['url'].str.contains(pattern, case=False, na=False)]

    report = {
        'total_logs_analyzed': int(len(df)),
        'brute_force_alerts': int(len(suspicious_ips)),
        'suspicious_ips': suspicious_ips,
        'sqli_alerts': int(len(sqli_matches)),
    }

    print('=== RAPPORT D\'ANALYSE DATA-DRIVEN SECURITY ===')
    print(json.dumps(report, indent=2))

  except Exception as e:
    print(f'Erreur lors de l\'analyse : {e}')
    raise e


if __name__ == '__main__':
  analyze_logs()