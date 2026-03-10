import urllib.request, json
url = "*REMOVED-DISCORD-WEBHOOK*"
payload = json.dumps({"content": "teste webhook"}).encode()
req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
try:
    urllib.request.urlopen(req, timeout=5)
    print("OK")
except Exception as e:
    print("ERRO:", e)
