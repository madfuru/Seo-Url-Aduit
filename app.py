import io, re, os, datetime as dt
import re as _re
import time
import json
from urllib.parse import urlparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError, wait
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask import Response
from werkzeug.exceptions import HTTPException
from bs4 import BeautifulSoup
from pptx import Presentation
import os, requests
import threading


app = Flask(__name__)
# allow all origins (simplest); later you can restrict to your WP domain
CORS(app, resources={r"/*": {"origins": "*"}})

# ---------- helpers ----------
UA = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}


def fetch(url, timeout=12):
    return requests.get(url, timeout=timeout, headers=UA, allow_redirects=True)

def safe_text(el):
    return (el.get_text(" ", strip=True) if el else "").strip()

def domain_from_url(u):
    return urlparse(u).netloc.lower()


# --- RDAP with quick universal endpoint first ---
def _rdap_events_to_dates(j):
    created = expires = None
    for e in (j.get("events") or []):
        act = (e.get("eventAction") or "").lower()
        if act in ("registration","creation"): created = e.get("eventDate")
        if act in ("expiration","expiry","expire"): expires = e.get("eventDate")
    fmt = lambda d: None if not d else d.split("T")[0]
    return fmt(created), fmt(expires)


def get_domain_info(u):
    dom = domain_from_url(u)

    # 1) Simple universal fallback first
    try:
        j = requests.get(f"https://rdap.org/domain/{dom}", timeout=8).json()
        created, expires = _rdap_events_to_dates(j)
        expiry_days = None
        if expires:
            d0 = dt.datetime.utcnow().date()
            d1 = dt.datetime.fromisoformat(expires.replace("Z","")).date()
            expiry_days = (d1 - d0).days
        registrar = None
        # try to pull a human registrar name if present
        for ent in j.get("entities", []) or []:
            if ent.get("roles") and "registrar" in [r.lower() for r in ent["roles"]]:
                va = (ent.get("vcardArray") or [None, []])[1]
                # find org/name fields in vcard
                for item in va:
                    if item and len(item) >= 4 and item[0] in ("fn","org"):
                        registrar = item[3]
                        break
                if registrar: break
        return {"created": created, "expiry": expires, "days_to_expire": expiry_days, "registrar": registrar}
    except Exception:
        pass

    # 2) IANA bootstrap fallback
    try:
        tld = dom.split(".")[-1]
        boot = requests.get("https://data.iana.org/rdap/dns.json", timeout=8).json()
        servers = [s for s in boot.get("services", []) if any(tld == x for x in s[0])]
        if servers:
            base = servers[0][1][0].rstrip("/")
            j = requests.get(f"{base}/domain/{dom}", timeout=8).json()
            created, expires = _rdap_events_to_dates(j)
            expiry_days = None
            if expires:
                d0 = dt.datetime.utcnow().date()
                d1 = dt.datetime.fromisoformat(expires.replace("Z","")).date()
                expiry_days = (d1 - d0).days
            registrar = None
            for ent in j.get("entities", []) or []:
                if ent.get("roles") and "registrar" in [r.lower() for r in ent["roles"]]:
                    va = (ent.get("vcardArray") or [None, []])[1]
                    for item in va:
                        if item and len(item) >= 4 and item[0] in ("fn","org"):
                            registrar = item[3]
                            break
                    if registrar: break
            return {"created": created, "expiry": expires, "days_to_expire": expiry_days, "registrar": registrar}
    except Exception:
        pass

    return {"created": None, "expiry": None, "days_to_expire": None, "registrar": None}

# ---------- PSI ----------
PSI_SEM = threading.Semaphore(2)  # limit concurrent /psi calls per worker
PSI_CACHE = {}                    # (url, strategy) -> (timestamp, json)
PSI_TTL = 60*60*24                # 24h
PSI_CACHE_MAX = 50  

# at top of file (once)
from math import ceil

# ---------- PSI ----------
PSI_CACHE = {}
PSI_TTL = 60*60*24   # 24h
PSI_CACHE_MAX = 50   # limit cache size

def _psi_call(url, strategy, key=None, timeout=60, tries=2):
    # ensure scheme
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    now = time.time()
    ck = (url, strategy)
    cached = PSI_CACHE.get(ck)
    if cached and now - cached[0] < PSI_TTL:
        return cached[1]

    base = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"

    def do():
        params = {"url": url, "strategy": strategy}
        if key:
            params["key"] = key
        return requests.get(base, params=params, timeout=timeout)

    last_err = None
    for attempt in range(1, tries+1):
        try:
            r = do()
            # Try to parse JSON always
            try:
                data = r.json()
            except Exception:
                data = {"error": {"message": f"Non-JSON from PSI (HTTP {r.status_code})"}}

            # If PSI returned error, include status/code details for visibility
            if "error" in data:
                err = data["error"]
                # Example: {"code":400,"status":"INVALID_ARGUMENT","message":"..."}
                msg = err.get("message","PSI error")
                status = err.get("status")
                code = err.get("code")
                data["error"]["message"] = f"{msg} (status={status}, code={code})"

            # cache (with eviction)
            if len(PSI_CACHE) >= PSI_CACHE_MAX:
                oldest = min(PSI_CACHE, key=lambda k: PSI_CACHE[k][0])
                PSI_CACHE.pop(oldest, None)
            PSI_CACHE[ck] = (time.time(), data)
            return data

        except (requests.Timeout, requests.ConnectionError) as e:
            last_err = f"{type(e).__name__}: {e}"
            time.sleep(0.7 * (2 ** (attempt-1)))  # small backoff
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            break

    return {"error": {"message": f"PSI request failed after {tries} tries: {last_err}"}}


def _psi_parse(j):
    if not j or "error" in j or not j.get("lighthouseResult"):
        # return the error string so UI can show it
        return None, (j.get("error", {}) or {}).get("message", "No PSI data")

    lhr = j["lighthouseResult"]
    audits = lhr.get("audits", {})
    cats = lhr.get("categories", {})
    perf = cats.get("performance", {}).get("score")

    def val(k):
        a = audits.get(k, {}) or {}
        return a.get("numericValue", a.get("displayValue"))

    return {
        "performance_score": round((perf or 0) * 100) if perf is not None else None,
        "fcp": val("first-contentful-paint"),
        "lcp": val("largest-contentful-paint"),
        "cls": (audits.get("cumulative-layout-shift", {}) or {}).get("numericValue"),
        "tbt": (audits.get("total-blocking-time", {}) or {}).get("numericValue"),
        "inp": (audits.get("experimental-interaction-to-next-paint", {}) or {}).get("numericValue"),
    }, None




def get_pagespeed_both(url):
    key = os.getenv("PSI_KEY")  # must be ENV VAR NAME
    # Desktop first
    d_raw = _psi_call(url, "desktop", key=key, timeout=60, tries=2)
    desktop, d_err = _psi_parse(d_raw)
    # Mobile next (shorter on purpose)
    m_raw = _psi_call(url, "mobile",  key=key, timeout=60, tries=1)
    mobile,  m_err = _psi_parse(m_raw)
    return {
        "desktop": desktop, "desktop_error": d_err,
        "mobile":  mobile,  "mobile_error":  m_err,
        "using_key": bool(key)
    }



# ---------- fast link checker ----------
def _fast_status(u):
    try:
        r = requests.head(u, timeout=3, allow_redirects=True, headers=UA)
        code = r.status_code
        if code in (403, 405):
            r = requests.get(u, timeout=4, allow_redirects=True, stream=False, headers=UA)
            code = r.status_code
        return {"href": u, "status": code}
    except Exception:
        return {"href": u, "status": 0}

# ---------- analyzer ----------
def analyze_html(url):
    issues, links = [], []
    try:
        res = fetch(url, timeout=8)
        if res.status_code != 200:
            issues.append({"severity":"error","message":f"HTTP status {res.status_code} (not 200)."})
        if not url.startswith("https://"):
            issues.append({"severity":"warn","message":"URL is not HTTPS."})

        soup = BeautifulSoup(res.text, "html.parser")

        title = (soup.find("title").get_text(" ", strip=True) if soup.find("title") else "").strip()
        if not title: issues.append({"severity":"error","message":"Missing <title>."})
        elif len(title) > 60: issues.append({"severity":"warn","message":"Title length > 60 characters."})

        md = soup.find("meta", attrs={"name":"description"})
        desc = (md.get("content","").strip() if md else "")
        if not desc: issues.append({"severity":"warn","message":"Missing meta description."})
        elif len(desc) > 160: issues.append({"severity":"warn","message":"Meta description > 160 characters."})

        h1s = [h.get_text(" ", strip=True) for h in soup.find_all(_re.compile("^h1$"))]
        if len(h1s)==0: issues.append({"severity":"warn","message":"Missing H1."})
        elif len(h1s)>1: issues.append({"severity":"warn","message":f"Multiple H1s ({len(h1s)})."})

        can = soup.find("link", rel="canonical")
        if not can or not can.get("href"):
            issues.append({"severity":"warn","message":"Missing canonical link."})
        else:
            try:
                cr = fetch(can.get("href"), timeout=4)
                if cr.status_code != 200:
                    issues.append({"severity":"warn","message":"Canonical URL not returning 200."})
            except Exception:
                issues.append({"severity":"warn","message":"Canonical URL not reachable."})

        robots_meta = soup.find("meta", attrs={"name":"robots"})
        if robots_meta and "noindex" in robots_meta.get("content","").lower():
            issues.append({"severity":"error","message":"Page has noindex meta."})

        # super-fast image checks (no big HEAD calls)
        noalt = sum(1 for img in soup.find_all("img") if not (img.get("alt") or "").strip())
        if noalt > 0:
            issues.append({"severity":"warn","message":f"{noalt} image(s) without alt."})

        # tiny same-domain link sample (<=6) with short timeouts
        page_host = urlparse(url).netloc.lower()
        cands = []
        for a in soup.find_all("a", limit=120):
            href = a.get("href"); 
            if not href or href.startswith("#"): continue
            full = href if href.startswith("http") else requests.compat.urljoin(url, href)
            if urlparse(full).netloc.lower() == page_host:
                cands.append(full)
            if len(cands) >= 6: break

        if cands:
            with ThreadPoolExecutor(max_workers=6) as ex:
                futs = [ex.submit(lambda u: requests.head(u, timeout=2, allow_redirects=True, headers=UA), c) for c in cands]
                for i, f in enumerate(futs):
                    try:
                        r = f.result(timeout=3)
                        links.append({"href": cands[i], "status": r.status_code})
                    except Exception:
                        links.append({"href": cands[i], "status": 0})

        return {"issues": issues, "links": links}
    except Exception:
        return {"issues":[{"severity":"error","message":"Fetch failed or invalid HTML."}], "links":[]}
# ---------- routes ----------
@app.route("/")
def health():
    return jsonify({"ok": True, "service": "seo-url-audit"})

@app.route("/psi")
def psi():
    url = request.args.get("url","").strip()
    if not url: return jsonify({"error":"missing url"}), 400
    if not os.getenv("PSI_KEY"): return jsonify({"error":"psikey_missing"}), 200
    if not PSI_SEM.acquire(blocking=False):
        return jsonify({"error":"busy", "message":"Please retry in a moment"}), 429
    try:
        return jsonify(get_pagespeed_both(url)), 200
    finally:
        PSI_SEM.release()

@app.errorhandler(Exception)
def _any_error(e):
    # Log the stack trace in Render logs, but don't 500 the browser.
    app.logger.exception(f"Unhandled error: {e}")
    return jsonify({"error": "server_error", "detail": str(e)[:120]}), 200

@app.route("/debug/psikey")
def debug_psikey():
    import os
    return jsonify({"using_key": bool(os.getenv("PSI_KEY"))})

@app.route("/analyze")
def analyze():
    url = request.args.get("url","").strip()
    if not url:
        return jsonify({"error":"missing url"}), 400

    skip_psi = request.args.get("skip_psi", "0") == "1"

    results = {"speed": {}, "domain": {}, "seo": {"issues":[]}, "links": []}

    def _speed():  return ("speed", get_pagespeed_both(url))
    def _domain(): return ("domain", get_domain_info(url))
    def _seo():
        x = analyze_html(url)
        return ("seo_links", x)

    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = []
        if not skip_psi:
            futs.append(ex.submit(_speed))
        futs += [ex.submit(_domain), ex.submit(_seo)]

        done, not_done = wait(futs, timeout=14)  # shorter so UI is snappy
        for f in not_done: f.cancel()

        for f in done:
            try:
                k, v = f.result()
                if k == "seo_links":
                    results["seo"]   = {"issues": v.get("issues", [])}
                    results["links"] = v.get("links", [])
                else:
                    results[k] = v
            except Exception as e:
                app.logger.warning(f"worker failed: {e}")

    return jsonify(results), 200

@app.route("/favicon.ico")
def favicon():
    return Response(status=204)

@app.route("/report")
def report():
    url = request.args.get("url","").strip()
    if not url:
        return "missing url", 400

    speed_both = get_pagespeed_both(url)
    # prefer desktop; else mobile
    sp = speed_both.get("desktop") or speed_both.get("mobile") or {}
    sp_err = speed_both.get("desktop_error") or speed_both.get("mobile_error")

    data = {
        "speed": sp,
        "domain": get_domain_info(url),
        "seo": analyze_html(url),
        "speed_error": sp_err
    }

    prs = Presentation()
    s1 = prs.slides.add_slide(prs.slide_layouts[0])
    s1.shapes.title.text = "SEO URL Audit Report"
    s1.placeholders[1].text = url

    s2 = prs.slides.add_slide(prs.slide_layouts[1])
    s2.shapes.title.text = "Core Web Vitals"
    body = s2.placeholders[1].text_frame
    if sp:
        for k,v in [("Performance", sp.get("performance_score")), ("FCP", sp.get("fcp")),
                    ("LCP", sp.get("lcp")), ("CLS", sp.get("cls")), ("INP/TBT", sp.get("inp") or sp.get("tbt"))]:
            p = body.add_paragraph(); p.text = f"{k}: {v}"
    else:
        p = body.add_paragraph(); p.text = f"Unavailable: {sp_err or 'No PSI data'}"

    s3 = prs.slides.add_slide(prs.slide_layouts[1])
    s3.shapes.title.text = "Domain Details"
    b3 = s3.placeholders[1].text_frame
    dm = data.get("domain",{})
    for k in ["created","expiry","days_to_expire","registrar"]:
        p = b3.add_paragraph(); p.text = f"{k}: {dm.get(k)}"

    s4 = prs.slides.add_slide(prs.slide_layouts[1])
    s4.shapes.title.text = "Critical / Important Issues"
    b4 = s4.placeholders[1].text_frame
    for i in data.get("seo",{}).get("issues",[])[:10]:
        p = b4.add_paragraph(); p.text = f"{i['severity'].upper()}: {i['message']}"

    s5 = prs.slides.add_slide(prs.slide_layouts[1])
    s5.shapes.title.text = "Broken Links (sample)"
    b5 = s5.placeholders[1].text_frame
    bad = [l for l in data.get("seo",{}).get("links",[]) if l.get("status",200) >= 400][:10]
    if not bad:
        p = b5.add_paragraph(); p.text = "None found"
    else:
        for l in bad:
            p = b5.add_paragraph(); p.text = f"{l['status']} — {l['href']}"

    buf = io.BytesIO(); prs.save(buf); buf.seek(0)
    fname = f"SEO_Audit_{domain_from_url(url)}.pptx"
    return send_file(buf, mimetype="application/vnd.openxmlformats-officedocument.presentationml.presentation",
                     as_attachment=True, download_name=fname)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)






























