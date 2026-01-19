import os, time, json
from flask import Flask, request, jsonify
from seranking import SERankingClient, clean_domain
from report_docx import fill_docx

app = Flask(__name__)

TOKEN = os.getenv("SERANKING_TOKEN", "")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs")
TEMPLATE_PATH = os.getenv("TEMPLATE_PATH", "templates/seo-proposal-template.docx")

os.makedirs(OUTPUT_DIR, exist_ok=True)

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/audit")
def audit():
    data = request.get_json(force=True) or {}
    domain = clean_domain(data.get("domain", ""))
    if not domain:
        return jsonify({"error": "domain required"}), 400

    client = SERankingClient(TOKEN)

    audit_id = client.create_audit_standard(domain, max_pages=2000, max_depth=10)
    status = client.wait_until_finished(audit_id, poll_seconds=30, max_wait_seconds=3600)

    errors = client.get_audit_errors(audit_id)
    warnings = client.get_audit_warnings(audit_id)

    values = client.map_placeholders(domain, status, errors, warnings)

    # Save JSON
    ts = int(time.time())
    json_path = f"{OUTPUT_DIR}/{domain}-{ts}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(values, f, indent=2)

    # Save DOCX
    docx_path = f"{OUTPUT_DIR}/{domain}-{ts}.docx"
    fill_docx(TEMPLATE_PATH, docx_path, values)

    # In free hosting, easiest is: return the JSON + store docx.
    # Later you can add file hosting (S3/R2) and return a public link.
    return jsonify({
        "domain": domain,
        "audit_id": audit_id,
        "placeholders": values,
        "files": {
            "json": json_path,
            "docx": docx_path
        }
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
