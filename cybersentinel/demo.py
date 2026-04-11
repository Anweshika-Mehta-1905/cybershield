"""
Quick demo: tests the full prediction pipeline locally without running the server.
Run from project root:  python demo.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.models.decision_engine import predict

TEST_URLS = [
    ("https://github.com/torvalds/linux",              "benign"),
    ("http://192.168.1.105/admin/login?user=admin",    "malicious"),
    ("http://paypal-secure-update.tk/account/verify",  "malicious"),
    ("https://www.google.com/search?q=python",         "benign"),
    ("http://login.amazon.account-verify.xyz/update",  "malicious"),
    ("https://stackoverflow.com/questions/123456",     "benign"),
    ("http://bit.ly/%2F%2F192.168.0.1/phish",          "malicious"),
]

def bar(score, width=30):
    filled = int(score * width)
    return "█" * filled + "░" * (width - filled)

print("=" * 70)
print("  CyberShield · Hybrid Detection Demo")
print("  3-Layer: Autoencoder + Logistic Regression + WFA")
print("=" * 70)

correct = 0
for url, expected in TEST_URLS:
    result = predict(url)
    verdict = "MALICIOUS" if result.is_malicious else "BENIGN"
    ok = (verdict.lower() == expected)
    correct += ok

    print(f"\nURL: {url[:65]}")
    print(f"  ML Score  : {bar(result.ml_score, 20)} {result.ml_score:.4f}")
    print(f"  WFA Score : {bar(result.wfa_score, 20)} {result.wfa_score:.4f}")
    print(f"  Final     : {bar(result.final_score, 20)} {result.final_score:.4f}  [{result.risk_level}]")
    print(f"  Verdict   : {'✅' if ok else '❌'} {verdict}  (expected: {expected.upper()})")
    if result.triggered_features:
        print(f"  Triggers  : {', '.join(result.triggered_features[:3])}")
    print(f"  WFA Path  : {' → '.join(result.wfa_path)}")

print("\n" + "=" * 70)
print(f"  Accuracy: {correct}/{len(TEST_URLS)} ({correct/len(TEST_URLS)*100:.0f}%)")
print("=" * 70)
