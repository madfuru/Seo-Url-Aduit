import io, re, os, datetime as dt
import re as _re
from urllib.parse import urlparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError, wait
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from bs4 import BeautifulSoup
from pptx import Presentation
import os, requests

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
PSI_CACHE = {}
PSI_TTL = 60*60*24
def _psi_call(url, strategy, key=None, timeout=22):
    base = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
    params = {"url": url, "strategy": strategy}
    if key: params["key"] = key
    r = requests.get(base, params=params, timeout=timeout)
    try:
        return r.json()
    except Exception:
        return {"error": {"message": f"Non-JSON from PSI (HTTP {r.status_code})"}}

def _psi_parse(j):
    if not j or "error" in j or not j.get("lighthouseResult"):
        return None, (j.get("error", {}) or {}).get("message", "No PSI data")
    lhr = j.get("lighthouseResult", {}) or {}
    audits = lhr.get("audits", {}) or {}
    cats = lhr.get("categories", {}) or {}
    perf = cats.get("performance", {}).get("score")
    def val(k):
        a = audits.get(k, {}) or {}
        return a.get("numericValue", a.get("displayValue"))
    return {
        "performance_score": round((perf or 0)*100) if perf is not None else None,
        "fcp": val("first-contentful-paint"),
        "lcp": val("largest-contentful-paint"),
        "cls": (audits.get("cumulative-layout-shift", {}) or {}).get("numericValue"),
        "tbt": (audits.get("total-blocking-time", {}) or {}).get("numericValue"),
        "inp": (audits.get("experimental-interaction-to-next-paint", {}) or {}).get("numericValue"),
    }, None

def get_pagespeed_both(url):
    key = os.getenv("AIzaSyACCvLvtwEshUM1YGz8U2RNDzihEJ3dJJE")
    desk_raw = _psi_call(url, "desktop", key=key, timeout=22)
    desktop, desk_err = _psi_parse(desk_raw)
    mob_raw  = _psi_call(url, "mobile",  key=key, timeout=22)
    mobile,  mob_err  = _psi_parse(mob_raw)
    return {
        "desktop": desktop, "desktop_error": desk_err,
        "mobile":  mobile,  "mobile_error":  mob_err
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

@app.errorhandler(Exception)
def _any_error(e):
    # Log the stack trace in Render logs, but don't 500 the browser.
    app.logger.exception(f"Unhandled error: {e}")
    return jsonify({"error": "server_error", "detail": str(e)[:120]}), 200

@app.route("/analyze")
def analyze():
    url = request.args.get("url","").strip()
    if not url:
        return jsonify({"error":"missing url"}), 400

    results = {"speed": {}, "domain": {}, "seo": {"issues":[]}, "links": []}

    def _speed():  return ("speed", get_pagespeed_both(url))
    def _domain(): return ("domain", get_domain_info(url))
    def _seo():
        x = analyze_html(url)
        return ("seo_links", x)

    # run in parallel with a hard 18s budget
    with ThreadPoolExecutor(max_workers=3) as ex:
        fut_map = {
            ex.submit(_speed): "speed",
            ex.submit(_domain): "domain",
            ex.submit(_seo): "seo_links"
        }
        done, not_done = wait(fut_map.keys(), timeout=18)
        # cancel anything slow
        for f in not_done:
            f.cancel()
        # collect what we have
        for f in done:
            try:
                k, v = f.result()
                if k == "seo_links":
                    results["seo"] = {"issues": v.get("issues", [])}
                    results["links"] = v.get("links", [])
                else:
                    results[k] = v
            except Exception as e:
                app.logger.warning(f"worker {fut_map[f]} failed: {e}")

    return jsonify(results)


@app.route("/report")
def report():
    url = request.args.get("url","").strip()
    if not url:
        return "missing url", 400
    data = {"speed": get_pagespeed(url), "domain": get_domain_info(url), "seo": analyze_html(url)}
    prs = Presentation()
    s1 = prs.slides.add_slide(prs.slide_layouts[0])
    s1.shapes.title.text = "SEO URL Audit Report"
    s1.placeholders[1].text = url

    s2 = prs.slides.add_slide(prs.slide_layouts[1])
    s2.shapes.title.text = "Core Web Vitals"
    body = s2.placeholders[1].text_frame
    sp = data.get("speed",{})
    for k,v in [("Performance", sp.get("performance_score")), ("FCP", sp.get("fcp")),
                ("LCP", sp.get("lcp")), ("CLS", sp.get("cls")), ("INP/TBT", sp.get("inp") or sp.get("tbt"))]:
        p = body.add_paragraph(); p.text = f"{k}: {v}"

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









