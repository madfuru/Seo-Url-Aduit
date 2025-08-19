import io, re, json, math, time, socket, datetime as dt
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_file
import requests
from bs4 import BeautifulSoup
from flask import Flask
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)  # allow browser calls from your WP domain

# ---------- Helpers ----------
def fetch(url, timeout=20):
    return requests.get(url, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})

def safe_text(el):
    return (el.get_text(" ", strip=True) if el else "").strip()

def domain_from_url(u):
    return urlparse(u).netloc.lower()

# ----- WHOIS / RDAP -----
def get_domain_info(u):
    dom = domain_from_url(u)
    # Try RDAP first (free, standardized)
    try:
        # Find RDAP server
        tld = dom.split(".")[-1]
        # IANA bootstrap
        rdap_boot = requests.get("https://data.iana.org/rdap/dns.json", timeout=15).json()
        servers = [s for s in rdap_boot["services"] if any(tld == x for x in s[0])]
        if servers:
            base = servers[0][1][0].rstrip("/")
            rdap = requests.get(f"{base}/domain/{dom}", timeout=20).json()
            created = next((e["eventDate"] for e in rdap.get("events", []) if e.get("eventAction")=="registration"), None)
            expires = next((e["eventDate"] for e in rdap.get("events", []) if e.get("eventAction")=="expiration"), None)
            registrar = (rdap.get("entities",[{}])[0].get("vcardArray",[None,[]])[1][1][3] 
                         if rdap.get("entities") else None)
            def fmt(d): 
                return None if not d else d.split("T")[0]
            expiry_days = None
            if expires:
                d0 = dt.datetime.utcnow().date()
                d1 = dt.datetime.fromisoformat(expires.replace("Z","")).date()
                expiry_days = (d1 - d0).days
            return {
                "created": fmt(created),
                "expiry": fmt(expires),
                "days_to_expire": expiry_days,
                "registrar": registrar
            }
    except Exception:
        pass
    # If RDAP fails, return minimal
    return {"created": None, "expiry": None, "days_to_expire": None, "registrar": None}

# ----- Google PSI (no key needed for basic; key recommended for quota) -----


def _parse_psi(j):
    lhr = j.get("lighthouseResult", {}) or {}
    audits = lhr.get("audits", {}) or {}
    cats = lhr.get("categories", {}) or {}
    perf = cats.get("performance", {}).get("score")
    def val(key):
        a = audits.get(key, {}) or {}
        # prefer numericValue; fallback to displayValue string
        return a.get("numericValue", a.get("displayValue"))
    out = {
        "performance_score": round((perf or 0)*100) if perf is not None else None,
        "fcp": val("first-contentful-paint"),
        "lcp": val("largest-contentful-paint"),
        "cls": (audits.get("cumulative-layout-shift", {}) or {}).get("numericValue"),
        "tbt": (audits.get("total-blocking-time", {}) or {}).get("numericValue"),
        "inp": (audits.get("experimental-interaction-to-next-paint", {}) or {}).get("numericValue"),
    }
    return out

def get_pagespeed(url):
    base = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
    key = os.getenv("PSI_KEY")  # optional; add in Render env later if needed
    try:
        params = {"url": url, "strategy": "mobile"}
        if key: params["key"] = key
        r = requests.get(base, params=params, timeout=60)
        j = r.json()
        if "error" in j or not j.get("lighthouseResult"):
            # fallback to desktop
            params["strategy"] = "desktop"
            r = requests.get(base, params=params, timeout=60)
            j = r.json()
        if "error" in j or not j.get("lighthouseResult"):
            return {}
        return _parse_psi(j)
    except Exception:
        return {}

# ----- On-page checks & links -----
def analyze_html(url):
    issues = []
    links = []
    try:
        res = fetch(url)
        status = res.status_code
        if status != 200:
            issues.append({"severity":"error","message":f"HTTP status {status} (not 200)."})
        if not url.startswith("https://"):
            issues.append({"severity":"warn","message":"URL is not HTTPS."})
        soup = BeautifulSoup(res.text, "html.parser")

        # title
        title = safe_text(soup.find("title"))
        if not title:
            issues.append({"severity":"error","message":"Missing <title>."})
        elif len(title) > 60:
            issues.append({"severity":"warn","message":"Title length > 60 characters."})

        # meta description
        md = soup.find("meta", attrs={"name":"description"})
        desc = (md.get("content","").strip() if md else "")
        if not desc:
            issues.append({"severity":"warn","message":"Missing meta description."})
        elif len(desc) > 160:
            issues.append({"severity":"warn","message":"Meta description > 160 characters."})

        # H1
        h1s = [safe_text(h) for h in soup.find_all(re.compile("^h1$"))]
        if len(h1s) == 0:
            issues.append({"severity":"warn","message":"Missing H1."})
        elif len(h1s) > 1:
            issues.append({"severity":"warn","message":f"Multiple H1s ({len(h1s)})."})

        # canonical
        can = soup.find("link", rel="canonical")
        if not can or not can.get("href"):
            issues.append({"severity":"warn","message":"Missing canonical link."})
        else:
            try:
                cr = fetch(can.get("href"))
                if cr.status_code != 200:
                    issues.append({"severity":"warn","message":"Canonical URL not returning 200."})
            except Exception:
                issues.append({"severity":"warn","message":"Canonical URL not reachable."})

        # robots / noindex
        robots_meta = soup.find("meta", attrs={"name":"robots"})
        if robots_meta and "noindex" in robots_meta.get("content","").lower():
            issues.append({"severity":"error","message":"Page has noindex meta."})

        # images
        big_imgs = 0
        noalt_imgs = 0
        for img in soup.find_all("img"):
            if not img.get("alt","").strip():
                noalt_imgs += 1
            src = img.get("src")
            if not src: continue
            try:
                img_url = src if src.startswith("http") else requests.compat.urljoin(url, src)
                ih = requests.head(img_url, timeout=10, allow_redirects=True)
                size = ih.headers.get("content-length")
                if size and size.isdigit() and int(size) > 150*1024:
                    big_imgs += 1
            except Exception:
                pass
        if noalt_imgs > 0:
            issues.append({"severity":"warn","message":f"{noalt_imgs} image(s) without alt."})
        if big_imgs > 0:
            issues.append({"severity":"warn","message":f"{big_imgs} large image(s) >150KB."})

        # links (sample up to 100)
                # links (sample fast & safe)
        page_host = urlparse(url).netloc.lower()
        a_tags = soup.find_all("a", limit=200)  # collect more, we'll filter
        sampled = []
        for a in a_tags:
            href = a.get("href")
            if not href or href.startswith("#"):
                continue
            full = href if href.startswith("http") else requests.compat.urljoin(url, href)
            host = urlparse(full).netloc.lower()
            # only same-domain links to keep checks fast & meaningful
            if host != page_host:
                continue
            sampled.append(full)
            if len(sampled) >= 40:  # hard cap
                break

        for full in sampled:
            try:
                hr = requests.head(full, timeout=6, allow_redirects=True)
                code = hr.status_code
                # some servers block HEAD; fallback to GET (no content)
                if code == 405 or code == 403:
                    gr = requests.get(full, timeout=8, allow_redirects=True, stream=False)
                    code = gr.status_code
                links.append({"href": full, "status": code})
            except Exception:
                links.append({"href": full, "status": 0})


        return {"issues": issues, "links": links}
    except Exception as e:
        return {"issues":[{"severity":"error","message":"Fetch failed or invalid HTML."}], "links":[]}

# ---------- Routes ----------
@app.route("/analyze")
def analyze():
    url = request.args.get("url","").strip()
    if not url:
        return jsonify({"error":"missing url"}), 400
    speed = get_pagespeed(url)
    domain = get_domain_info(url)
    seo = analyze_html(url)
    return jsonify({"speed": speed, "domain": domain, "seo": {"issues": seo["issues"]}, "links": seo["links"]})

@app.route("/")
def home():
    return jsonify({"ok": True, "service": "seo-url-audit"})

# ---------- PPTX ----------
from pptx import Presentation
from pptx.util import Inches, Pt

def build_ppt(data, url):
    prs = Presentation()
    # Title slide
    slide = prs.slides.add_slide(prs.slide_layouts[0])
    slide.shapes.title.text = "SEO URL Audit Report"
    slide.placeholders[1].text = url

    # Performance slide
    s2 = prs.slides.add_slide(prs.slide_layouts[1])
    s2.shapes.title.text = "Core Web Vitals"
    body = s2.placeholders[1].text_frame
    sp = data.get("speed", {})
    items = [
        ("Performance", sp.get("performance_score")),
        ("FCP", sp.get("fcp")),
        ("LCP", sp.get("lcp")),
        ("CLS", sp.get("cls")),
        ("INP/TBT", sp.get("inp") or sp.get("tbt")),
    ]
    for k,v in items:
        p = body.add_paragraph(); p.text = f"{k}: {v}"

    # Domain slide
    s3 = prs.slides.add_slide(prs.slide_layouts[1])
    s3.shapes.title.text = "Domain Details"
    b3 = s3.placeholders[1].text_frame
    dm = data.get("domain", {})
    for k in ["created","expiry","days_to_expire","registrar"]:
        p = b3.add_paragraph(); p.text = f"{k}: {dm.get(k)}"

    # Critical issues slide
    s4 = prs.slides.add_slide(prs.slide_layouts[1])
    s4.shapes.title.text = "Critical / Important Issues"
    b4 = s4.placeholders[1].text_frame
    issues = data.get("seo",{}).get("issues", [])
    for i in issues[:10]:
        p = b4.add_paragraph(); p.text = f"{i['severity'].upper()}: {i['message']}"

    # Broken links slide
    s5 = prs.slides.add_slide(prs.slide_layouts[1])
    s5.shapes.title.text = "Broken Links (sample)"
    b5 = s5.placeholders[1].text_frame
    bad = [l for l in data.get("links",[]) if l.get("status",200) >= 400][:10]
    if not bad:
        p = b5.add_paragraph(); p.text = "None found"
    else:
        for l in bad:
            p = b5.add_paragraph(); p.text = f"{l['status']} — {l['href']}"

    return prs

@app.route("/report")
def report():
    url = request.args.get("url","").strip()
    if not url:
        return "missing url", 400
    data = {
        "speed": get_pagespeed(url),
        "domain": get_domain_info(url),
        "seo": analyze_html(url)
    }
    prs = build_ppt(data, url)
    buf = io.BytesIO()
    prs.save(buf); buf.seek(0)
    fname = f"SEO_Audit_{domain_from_url(url)}.pptx"
    return send_file(buf, mimetype="application/vnd.openxmlformats-officedocument.presentationml.presentation",
                     as_attachment=True, download_name=fname)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)




