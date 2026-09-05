import json
import pandas as pd


def analyze_logs():
  df = pd.read_csv("data/access_logs.csv")

  # 1. Détection Brute Force (> 5 échecs 401)
  failed_logins = df[df["status_code"] == 401]
  bf_attempts = failed_logins.groupby("ip_address").size()
  suspicious_ips = bf_attempts[bf_attempts > 5].index.tolist()

  # 2. Détection d'injection SQL
  sqli_patterns = ["UNION", "SELECT", "OR 1=1", "'--", "DROP"]
  pattern = "|".join(sqli_patterns)
  sqli_attempts = df[
      df["url"].str.contains(pattern, case=False, na=False)
  ]

  report = {
      "total_logs_analyzed": len(df),
      "brute_force_alerts": len(suspicious_ips),
      "suspicious_ips": suspicious_ips,
      "sqli_alerts": len(sqli_attempts),
  }

  print("=== RAPPORT D'ANALYSE DATA-DRIVEN SECURITY ===")
  print(json.dumps(report, indent=2))


if __name__ == "__main__":
  analyze_logs()