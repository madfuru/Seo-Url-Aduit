import time, re, requests

BASE_URL = "https://api.seranking.com/v1"

def clean_domain(domain_or_url: str) -> str:
    s = (domain_or_url or "").strip()
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = re.sub(r"^www\.", "", s, flags=re.I)
    s = s.split("/")[0].strip()
    return s

class SERankingClient:
    def __init__(self, token: str, timeout: int = 60):
        self.token = token.strip()
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {self.token}",
            "Accept": "application/json",
        })
        self.timeout = timeout

    def _req(self, method: str, path: str, *, params=None, json_body=None):
        url = f"{BASE_URL}{path}"
        headers = {}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        r = self.session.request(method, url, params=params, json=json_body, headers=headers, timeout=self.timeout)
        if not r.ok:
            raise RuntimeError(f"{r.status_code} {r.text}")
        return r.json()

    def create_audit_standard(self, domain: str, max_pages=2000, max_depth=10) -> int:
        d = clean_domain(domain)
        body = {"domain": d, "title": f"Auto audit - {d}", "settings": {"max_pages": max_pages, "max_depth": max_depth}}
        data = self._req("POST", "/site-audit/audits/standard", json_body=body)
        if "id" not in data:
            raise RuntimeError(f"No audit id: {data}")
        return int(data["id"])

    def get_audit_status(self, audit_id: int):
        data = self._req("GET", "/site-audit/audits/status", params={"audit_id": audit_id})
        return data[0] if isinstance(data, list) and data else data

    def wait_until_finished(self, audit_id: int, poll_seconds=30, max_wait_seconds=3600):
        start = time.time()
        while True:
            st = self.get_audit_status(audit_id)
            status = (st.get("status") or "").lower()
            if status in ("finished", "done", "completed", "success"):
                return st
            if time.time() - start > max_wait_seconds:
                raise TimeoutError(f"Not finished: {st}")
            time.sleep(poll_seconds)

    def get_audit_errors(self, audit_id: int):
        return self._req("GET", "/site-audit/audits/errors", params={"audit_id": audit_id})

    def get_audit_warnings(self, audit_id: int):
        return self._req("GET", "/site-audit/audits/warnings", params={"audit_id": audit_id})

    def map_placeholders(self, domain: str, status: dict, errors_raw, warnings_raw):
        # Start with safe defaults
        values = {
            "missing_meta_descriptions_pages": 0,
            "duplicate_h1_pages": 0,
            "duplicate_title_urls": 0,
            "broken_internal_links": 0,
            "slow_pages_over_3s": 0,
            "missing_alt_images": 0,
            "total_pages_with_errors": status.get("total_errors", 0) or 0,
            "total_pages_with_warnings": status.get("total_warnings", 0) or 0,
        }

        # IMPORTANT: You must inspect your actual issue "code" names once.
        # Print errors_raw/warnings_raw and map codes here correctly.

        return values
