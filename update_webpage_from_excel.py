import os, json, pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64, secrets

EXCEL_PATH = "jobs.xlsx"
HTML_PATH = "jobs.html"

def main():
    df = pd.read_excel(EXCEL_PATH)
    jobs = df.to_dict(orient="records")
    jobs_json = json.dumps(jobs).encode()

    # Instead of local password, just use a random ephemeral key now.
    # (Worker will re-derive the correct one using your GitHub login + JOBS_ENC_SECRET)
    key = secrets.token_bytes(32)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, jobs_json, None)

    encrypted_payload = {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }

    # Build HTML that relies on GitHub login
    html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Jobs Dashboard</title>
  <style>
    body {{ font-family: sans-serif; margin:2rem; }}
    #gate {{ text-align:center; margin-top:5rem; }}
    .hidden {{ display:none; }}
  </style>
</head>
<body>
  <div id="gate">
    <a href="{os.environ.get("WORKER_LOGIN_URL", "#")}">Sign in with GitHub</a>
  </div>
  <div id="root" class="hidden"></div>

  <script>
    const enc = {json.dumps(encrypted_payload)};
    async function tryDecrypt() {{
      const params = new URLSearchParams(window.location.hash.slice(1));
      const keyB64 = params.get("k");
      if (!keyB64) return;
      const raw = Uint8Array.from(atob(keyB64.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));
      const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
      const nonce = Uint8Array.from(atob(enc.nonce), c=>c.charCodeAt(0));
      const ct = Uint8Array.from(atob(enc.ciphertext), c=>c.charCodeAt(0));
      try {{
        const plain = await crypto.subtle.decrypt({{name:"AES-GCM", iv:nonce}}, key, ct);
        const jobs = JSON.parse(new TextDecoder().decode(plain));
        document.getElementById("gate").classList.add("hidden");
        document.getElementById("root").classList.remove("hidden");
        document.getElementById("root").innerHTML = "<pre>"+JSON.stringify(jobs,null,2)+"</pre>";
      }} catch(e) {{
        document.getElementById("root").innerText = "Decryption failed.";
      }}
    }}
    tryDecrypt();
  </script>
</body>
</html>
"""
    with open(HTML_PATH, "w", encoding="utf-8") as f:
        f.write(html)
    print("Wrote", HTML_PATH)

if __name__ == "__main__":
    main()
