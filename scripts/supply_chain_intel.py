#!/usr/bin/env python3
"""Build supply-chain research posts from security vendor RSS feeds.

The script is intentionally dependency-free so GitHub Actions can run it with
the stock Python runtime. It keeps local state, clusters related feed entries,
and asks OpenAI for one synthesized article per incident.
"""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import hashlib
import html
import json
import os
import re
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo


ROOT = Path(__file__).resolve().parents[1]
STATE_PATH = ROOT / ".data" / "supply-chain-intel" / "state.json"
POSTS_DIR = ROOT / "research" / "posts"
RESEARCH_PAGE = ROOT / "research.html"
DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5.5")
SITE_TIMEZONE = os.environ.get("SITE_TIMEZONE", "America/New_York")

DEFAULT_FEEDS = {
    "Socket": [
        "https://socket.dev/api/blog/feed.atom",
    ],
    "Endor Labs": [
        "https://www.endorlabs.com/blog/rss.xml",
    ],
    "Semgrep": [
        "https://semgrep.dev/blog/rss",
    ],
}

FEED_DISCOVERY_PAGES = {
    "Socket": ["https://socket.dev/blog", "https://socket.dev"],
    "Endor Labs": ["https://www.endorlabs.com/blog", "https://www.endorlabs.com"],
    "Semgrep": ["https://semgrep.dev/blog", "https://semgrep.dev"],
}

SUPPLY_CHAIN_TERMS = {
    "supply chain",
    "dependency",
    "dependencies",
    "package",
    "packages",
    "npm",
    "pypi",
    "maven",
    "rubygems",
    "nuget",
    "crate",
    "cargo",
    "typosquat",
    "typosquatting",
    "malware",
    "backdoor",
    "compromise",
    "maintainer",
    "protestware",
    "dependency confusion",
    "postinstall",
    "infostealer",
    "token theft",
    "github actions",
    "artifact",
    "open source",
}

NOISE_TERMS = {
    "webinar",
    "conference",
    "product update",
    "customer",
    "funding",
    "hiring",
    "release notes",
}

COLLABORATION_TERMS = {
    "partner",
    "partners with",
    "partnership",
    "collaboration",
    "collaborates with",
    "integration partner",
    "customer story",
    "case study",
    "webinar",
    "event",
    "joins",
    "appoints",
    "raises",
    "series a",
    "series b",
    "series c",
    "launch week",
}

NOISE_CATEGORIES = {
    "announcements",
    "case studies",
    "company news",
    "customer",
    "customer stories",
    "events",
    "partners",
    "press",
    "product",
    "product updates",
    "webinars",
}

STOP_WORDS = {
    "about",
    "after",
    "against",
    "attack",
    "attacks",
    "blog",
    "breaking",
    "campaign",
    "critical",
    "from",
    "github",
    "labs",
    "latest",
    "more",
    "new",
    "open",
    "package",
    "packages",
    "security",
    "semgrep",
    "socket",
    "software",
    "supply",
    "chain",
    "than",
    "that",
    "the",
    "this",
    "using",
    "with",
    "your",
}


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_now() -> str:
    return now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def local_now() -> dt.datetime:
    try:
        zone = ZoneInfo(SITE_TIMEZONE)
    except Exception:
        zone = dt.timezone.utc
    return now_utc().astimezone(zone)


def local_today() -> str:
    return local_now().date().isoformat()


def incident_display_date(incident: dict[str, Any]) -> str:
    return incident.get("discovered_on") or incident.get("created_at", "")[:10] or local_today()


def incident_lastmod_date(incident: dict[str, Any]) -> str:
    return incident.get("last_seen_on") or incident.get("updated_at", "")[:10] or incident_display_date(incident)


def local_date_from_iso(value: str) -> str:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return local_today()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    try:
        zone = ZoneInfo(SITE_TIMEZONE)
    except Exception:
        zone = dt.timezone.utc
    return parsed.astimezone(zone).date().isoformat()


def migrate_incident_dates(state: dict[str, Any]) -> bool:
    changed = False
    for incident in state.get("incidents", {}).values():
        if not incident.get("discovered_on"):
            incident["discovered_on"] = local_date_from_iso(incident.get("created_at") or incident.get("updated_at", ""))
            changed = True
        if not incident.get("last_seen_on"):
            incident["last_seen_on"] = local_date_from_iso(incident.get("updated_at") or incident.get("created_at", ""))
            changed = True
    return changed


def load_json(path: Path, fallback: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def slugify(value: str, fallback: str = "incident") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:80].strip("-") or fallback


def clean_text(value: str) -> str:
    value = re.sub(r"<[^>]+>", " ", value or "")
    value = html.unescape(value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def parse_date(value: str | None) -> str:
    if not value:
        return iso_now()
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return iso_now()


def date_from_iso(value: str) -> dt.datetime:
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return now_utc()


def fetch_url(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "arnabroy24-supply-chain-intel/1.0 (+https://arnabroy24.github.io)",
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def absolutize_url(url: str, base: str) -> str:
    return urllib.parse.urljoin(base, html.unescape(url))


def discover_feed_urls(source: str) -> list[str]:
    discovered: list[str] = []
    for page in FEED_DISCOVERY_PAGES.get(source, []):
        try:
            body = fetch_url(page).decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
        for match in re.finditer(r'<link[^>]+(?:application/(?:rss|atom)\+xml|application/xml|text/xml)[^>]+>', body, flags=re.I):
            href_match = re.search(r'href=["\']([^"\']+)["\']', match.group(0), flags=re.I)
            if href_match:
                discovered.append(absolutize_url(href_match.group(1), page))
        for href in re.findall(r'href=["\']([^"\']*(?:rss|feed|atom)[^"\']*\.xml[^"\']*)["\']', body, flags=re.I):
            discovered.append(absolutize_url(href, page))
    return list(dict.fromkeys(discovered))


def first_text(element: ET.Element, names: list[str]) -> str:
    for name in names:
        found = element.find(name)
        if found is not None and found.text:
            return found.text.strip()
    for child in list(element):
        if child.tag.split("}")[-1] in {n.split("}")[-1] for n in names} and child.text:
            return child.text.strip()
    return ""


def first_link(element: ET.Element) -> str:
    link = first_text(element, ["link", "{http://www.w3.org/2005/Atom}link"])
    if link:
        return link
    fallback = ""
    for child in list(element):
        if child.tag.split("}")[-1] == "link":
            href = child.attrib.get("href")
            rel = child.attrib.get("rel", "alternate")
            if href and rel == "alternate":
                return href
            if href and not fallback:
                fallback = href
    return fallback


def categories_for(element: ET.Element) -> list[str]:
    categories: list[str] = []
    for child in list(element):
        if child.tag.split("}")[-1] != "category":
            continue
        value = child.attrib.get("term") or child.text or ""
        value = clean_text(value).lower()
        if value:
            categories.append(value)
    return sorted(set(categories))


def parse_feed(source: str, url: str, payload: bytes) -> list[dict[str, Any]]:
    root = ET.fromstring(payload)
    tag = root.tag.split("}")[-1].lower()
    entries: list[ET.Element]
    atom = False
    if tag == "rss" or root.find("./channel") is not None:
        entries = root.findall("./channel/item")
    else:
        atom = True
        entries = root.findall("{http://www.w3.org/2005/Atom}entry") or root.findall("entry")

    items: list[dict[str, Any]] = []
    for entry in entries:
        if atom:
            title = first_text(entry, ["{http://www.w3.org/2005/Atom}title", "title"])
            link = first_link(entry)
            summary = first_text(entry, ["{http://www.w3.org/2005/Atom}summary", "{http://www.w3.org/2005/Atom}content", "summary", "content"])
            published = parse_date(first_text(entry, ["{http://www.w3.org/2005/Atom}published", "{http://www.w3.org/2005/Atom}updated", "published", "updated"]))
        else:
            title = first_text(entry, ["title"])
            link = first_link(entry)
            summary = first_text(entry, ["description", "summary", "{http://purl.org/rss/1.0/modules/content/}encoded"])
            published = parse_date(first_text(entry, ["pubDate", "date", "published", "updated"]))
        if not title or not link:
            continue
        item_id = hashlib.sha256(link.encode("utf-8")).hexdigest()[:16]
        items.append(
            {
                "id": item_id,
                "source": source,
                "feed_url": url,
                "title": clean_text(title),
                "url": link,
                "summary": clean_text(summary)[:1200],
                "categories": categories_for(entry),
                "published_at": published,
            }
        )
    return items


def get_feed_config() -> dict[str, list[str]]:
    override = os.environ.get("SUPPLY_CHAIN_FEEDS")
    if not override:
        return DEFAULT_FEEDS
    parsed = json.loads(override)
    return {str(k): [str(v) for v in values] for k, values in parsed.items()}


def fetch_all_feeds() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for source, urls in get_feed_config().items():
        for url in list(urls) + discover_feed_urls(source):
            try:
                payload = fetch_url(url)
                parsed = parse_feed(source, url, payload)
            except (urllib.error.URLError, ET.ParseError, TimeoutError, OSError) as exc:
                print(f"feed skipped: {source} {url} ({exc})", file=sys.stderr)
                continue
            if parsed:
                print(f"feed ok: {source} {url} ({len(parsed)} items)", file=sys.stderr)
                items.extend(parsed)
                break
    return items


def extract_article_text(payload: bytes) -> str:
    text = payload.decode("utf-8", errors="replace")
    text = re.sub(r"(?is)<(script|style|noscript|svg|form|nav|footer|header)[^>]*>.*?</\1>", " ", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p>|</li>|</h[1-6]>", "\n", text)
    text = clean_text(text)
    return text[:5000]


def enrich_with_article_text(item: dict[str, Any]) -> dict[str, Any]:
    if item.get("article_text"):
        return item
    try:
        item["article_text"] = extract_article_text(fetch_url(item["url"]))
    except (urllib.error.URLError, TimeoutError, OSError):
        item["article_text"] = ""
    return item


def looks_relevant(item: dict[str, Any]) -> bool:
    text = f"{item['title']} {item.get('summary', '')}".lower()
    categories = {category.lower() for category in item.get("categories", [])}
    has_strong_indicator = bool(extract_indicators(item)) or any(
        term in text
        for term in {
            "backdoor",
            "compromised",
            "credential stealer",
            "dependency confusion",
            "infostealer",
            "malicious package",
            "malware",
            "postinstall",
            "supply chain attack",
            "token theft",
            "trojanized",
            "typosquat",
            "worm",
        }
    )
    if categories.intersection(NOISE_CATEGORIES) and not has_strong_indicator:
        return False
    if any(term in text for term in COLLABORATION_TERMS) and not has_strong_indicator:
        return False
    if any(term in text for term in NOISE_TERMS) and not any(term in text for term in SUPPLY_CHAIN_TERMS):
        return False
    return any(term in text for term in SUPPLY_CHAIN_TERMS)


def token_set(text: str) -> set[str]:
    tokens = set(re.findall(r"[a-z0-9][a-z0-9._/-]{2,}", text.lower()))
    return {token.strip("-_/") for token in tokens if token not in STOP_WORDS}


def extract_indicators(item: dict[str, Any]) -> list[str]:
    text = f"{item['title']} {item.get('summary', '')}"
    patterns = [
        r"CVE-\d{4}-\d{4,7}",
        r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",
        r"@[a-z0-9][a-z0-9._-]+/[a-z0-9][a-z0-9._-]+",
        r"\b[a-z0-9][a-z0-9._-]+\.(?:js|py|jar|dll|exe)\b",
    ]
    found: set[str] = set()
    for pattern in patterns:
        found.update(match.lower() for match in re.findall(pattern, text, flags=re.I))
    quoted = re.findall(r"[`'\"]([@a-zA-Z0-9][a-zA-Z0-9._/-]{2,})[`'\"]", text)
    found.update(value.lower() for value in quoted if "/" in value or "-" in value or "." in value)
    return sorted(found)


def incident_key(item: dict[str, Any]) -> str:
    indicators = extract_indicators(item)
    if indicators:
        return slugify(indicators[0])
    tokens = sorted(token_set(f"{item['title']} {item.get('summary', '')}"))
    return slugify("-".join(tokens[:8]) or item["title"])


def find_cluster(item: dict[str, Any], incidents: dict[str, Any]) -> str | None:
    indicators = set(extract_indicators(item))
    tokens = token_set(f"{item['title']} {item.get('summary', '')}")
    best_slug = None
    best_score = 0.0
    for slug, incident in incidents.items():
        known_indicators = set(incident.get("indicators", []))
        if indicators and known_indicators and indicators.intersection(known_indicators):
            return slug
        known_tokens = set(incident.get("tokens", []))
        if not tokens or not known_tokens:
            continue
        score = len(tokens.intersection(known_tokens)) / max(len(tokens.union(known_tokens)), 1)
        if score > best_score:
            best_score = score
            best_slug = slug
    return best_slug if best_score >= 0.38 else None


def ensure_incident(item: dict[str, Any], state: dict[str, Any]) -> tuple[str, bool]:
    incidents = state.setdefault("incidents", {})
    slug = find_cluster(item, incidents)
    created = False
    if not slug:
        base = incident_key(item)
        slug = base
        counter = 2
        while slug in incidents:
            slug = f"{base}-{counter}"
            counter += 1
        incidents[slug] = {
            "slug": slug,
            "title": item["title"],
            "created_at": iso_now(),
            "updated_at": iso_now(),
            "discovered_on": local_today(),
            "last_seen_on": local_today(),
            "post_path": f"research/posts/{slug}.html",
            "sources": [],
            "source_urls": [],
            "source_ids": [],
            "indicators": [],
            "tokens": [],
        }
        created = True

    incident = incidents[slug]
    if item["id"] not in incident.setdefault("source_ids", []):
        incident["source_ids"].append(item["id"])
        incident.setdefault("sources", []).append(item)
        incident.setdefault("source_urls", []).append(item["url"])
        incident["updated_at"] = iso_now()
        incident["last_seen_on"] = local_today()
        created = True

    indicators = set(incident.get("indicators", []))
    indicators.update(extract_indicators(item))
    incident["indicators"] = sorted(indicators)
    tokens = set(incident.get("tokens", []))
    tokens.update(token_set(f"{item['title']} {item.get('summary', '')}"))
    incident["tokens"] = sorted(tokens)[:80]
    return slug, created


ARTICLE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "should_publish": {"type": "boolean"},
        "title": {"type": "string"},
        "dek": {"type": "string"},
        "incident_summary": {"type": "string"},
        "key_findings": {"type": "array", "items": {"type": "string"}},
        "affected_ecosystems": {"type": "array", "items": {"type": "string"}},
        "defender_actions": {"type": "array", "items": {"type": "string"}},
        "analysis": {"type": "string"},
        "source_notes": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "should_publish",
        "title",
        "dek",
        "incident_summary",
        "key_findings",
        "affected_ecosystems",
        "defender_actions",
        "analysis",
        "source_notes",
    ],
}


def openai_request(path: str, api_key: str, body: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"https://api.openai.com/v1/{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API error {exc.code}: {detail}") from exc


def extract_response_text(data: dict[str, Any]) -> str:
    if isinstance(data.get("output_text"), str):
        return data["output_text"]
    for item in data.get("output", []):
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"} and isinstance(content.get("text"), str):
                return content["text"]
    choices = data.get("choices", [])
    if choices:
        return choices[0].get("message", {}).get("content", "")
    return ""


def synthesize_article(incident: dict[str, Any], api_key: str, model: str) -> dict[str, Any]:
    sources = [
        {
            "source": source["source"],
            "title": source["title"],
            "url": source["url"],
            "published_at": source["published_at"],
            "summary": source.get("summary", ""),
            "article_text": source.get("article_text", ""),
        }
        for source in incident.get("sources", [])
    ]
    prompt = textwrap.dedent(
        """
        Create one original supply-chain security analysis from the source snippets.

        Requirements:
        - Merge duplicate coverage into one incident narrative.
        - Do not copy vendor phrasing.
        - Publish only if the sources describe a software supply-chain attack,
          compromised dependency, malicious package campaign, package ecosystem
          abuse, or directly relevant dependency risk.
        - Do not publish collaboration, partner, customer, webinar, funding,
          hiring, launch, or product announcement posts unless they add concrete
          facts about an actual attack or affected package ecosystem.
        - Focus on practical AppSec value: affected ecosystems, how exposure
          should be assessed, and what defenders should do next.
        - Mention uncertainty where the sources are incomplete.
        - Keep the article concise and professional.
        """
    ).strip()
    user_payload = json.dumps({"incident": incident["slug"], "sources": sources}, indent=2)
    body = {
        "model": model,
        "input": [
            {"role": "system", "content": "You are an application security researcher writing concise, source-grounded supply-chain incident analysis."},
            {"role": "user", "content": f"{prompt}\n\nSources:\n{user_payload}"},
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "supply_chain_article",
                "strict": True,
                "schema": ARTICLE_SCHEMA,
            }
        },
    }
    try:
        data = openai_request("responses", api_key, body)
    except RuntimeError:
        chat_body = {
            "model": model,
            "messages": body["input"],
            "response_format": {"type": "json_object"},
        }
        data = openai_request("chat/completions", api_key, chat_body)
    text = extract_response_text(data)
    return json.loads(text)


def page_header(title: str, description: str, canonical_path: str = "") -> str:
    canonical = f'  <link rel="canonical" href="https://arnabroy24.github.io/{canonical_path}" />\n' if canonical_path else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="description" content="{html.escape(description)}" />
  <meta name="theme-color" content="#0a1020" />
{canonical}  <title>{html.escape(title)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="../../styles.css" />
</head>
"""


def nav(prefix: str = "") -> str:
    return f"""  <a class="skip-link" href="#main">Skip to content</a>
  <header class="site-header">
    <div class="container nav-wrap">
      <a class="brand" href="{prefix}index.html#top" aria-label="Arnab Roy home"><span class="brand-mark">AR</span><span>Arnab Roy</span></a>
      <button class="menu-button" aria-expanded="false" aria-controls="main-nav">Menu</button>
      <nav id="main-nav" class="main-nav" aria-label="Primary navigation">
        <a href="{prefix}index.html#about">About</a>
        <a href="{prefix}index.html#expertise">Expertise</a>
        <a href="{prefix}index.html#experience">Experience</a>
        <a href="{prefix}research.html">Research</a>
        <a href="{prefix}index.html#credentials">Credentials</a>
        <a class="nav-cta" href="{prefix}index.html#contact">Contact</a>
      </nav>
    </div>
  </header>
"""


def footer(prefix: str = "") -> str:
    return f"""  <footer class="site-footer"><div class="container"><span>© <span id="year"></span> Arnab Roy</span><span>Portfolio and research notes.</span></div></footer>
  <script src="{prefix}script.js"></script>
</body>
</html>
"""


def render_post(slug: str, incident: dict[str, Any], article: dict[str, Any]) -> None:
    POSTS_DIR.mkdir(parents=True, exist_ok=True)
    title = article["title"].strip() or incident["title"]
    sources = incident.get("sources", [])
    source_links = "\n".join(
        f'          <a href="{html.escape(source["url"])}" target="_blank" rel="noreferrer">{html.escape(source["source"])}</a>'
        for source in sources
    )
    key_findings = "\n".join(f"          <li>{html.escape(item)}</li>" for item in article.get("key_findings", []))
    ecosystems = ", ".join(article.get("affected_ecosystems", [])) or "Not specified"
    actions = "\n".join(f"          <li>{html.escape(item)}</li>" for item in article.get("defender_actions", []))
    notes = "\n".join(f"          <li>{html.escape(item)}</li>" for item in article.get("source_notes", []))
    body = f"""{page_header(title, article.get("dek", ""), f"research/posts/{slug}.html")}<body class="article-page">
{nav("../../")}
  <main id="main">
    <article>
      <header class="article-header">
        <div class="container">
          <p class="article-meta">Discovered {html.escape(incident_display_date(incident))} / {len(sources)} source{"s" if len(sources) != 1 else ""}</p>
          <h1>{html.escape(title)}</h1>
          <p class="hero-copy">{html.escape(article.get("dek", ""))}</p>
          <div class="source-list">
{source_links}
          </div>
        </div>
      </header>
      <div class="article-body">
        <div class="container">
          <h2>What happened</h2>
          <p>{html.escape(article.get("incident_summary", ""))}</p>
          <h2>Key findings</h2>
          <ul>
{key_findings}
          </ul>
          <h2>Affected ecosystems</h2>
          <p>{html.escape(ecosystems)}</p>
          <h2>Security analysis</h2>
          <p>{html.escape(article.get("analysis", ""))}</p>
          <h2>Defender actions</h2>
          <ul>
{actions}
          </ul>
          <h2>Source notes</h2>
          <ul>
{notes}
          </ul>
        </div>
      </div>
    </article>
  </main>
{footer("../../")}
"""
    (POSTS_DIR / f"{slug}.html").write_text(body, encoding="utf-8")
    incident["title"] = title
    incident["dek"] = article.get("dek", "")
    incident["published"] = True
    incident["post_path"] = f"research/posts/{slug}.html"


def patch_existing_post_dates(state: dict[str, Any]) -> bool:
    changed = False
    for incident in state.get("incidents", {}).values():
        post_path = incident.get("post_path")
        if not incident.get("published") or not post_path:
            continue
        path = ROOT / post_path
        if not path.exists():
            continue
        original = path.read_text(encoding="utf-8")
        replacement = f'<p class="article-meta">Discovered {incident_display_date(incident)} /'
        updated = re.sub(r'<p class="article-meta">(?:Updated|Discovered) \d{4}-\d{2}-\d{2} /', replacement, original, count=1)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            changed = True
    return changed


def render_research_page(state: dict[str, Any]) -> None:
    incidents = [
        incident
        for incident in state.get("incidents", {}).values()
        if incident.get("published") and incident.get("post_path")
    ]
    incidents.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    if incidents:
        cards = "\n".join(
            f"""          <article class="research-card">
            <a href="{html.escape(incident["post_path"])}">
              <p class="research-meta">{html.escape(incident_display_date(incident))} / {len(incident.get("sources", []))} source{"s" if len(incident.get("sources", [])) != 1 else ""}</p>
              <h2>{html.escape(incident.get("title", "Supply-chain incident"))}</h2>
              <p>{html.escape(incident.get("dek", "Synthesized supply-chain incident analysis."))}</p>
            </a>
          </article>"""
            for incident in incidents
        )
    else:
        cards = """          <div class="empty-state">
            No research notes have been published yet. The scheduled workflow will add entries here after it finds relevant supply-chain coverage and opens a review PR.
          </div>"""

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="description" content="Arnab Roy's supply-chain security research notebook." />
  <meta name="theme-color" content="#0a1020" />
  <link rel="canonical" href="https://arnabroy24.github.io/research.html" />
  <title>Research | Arnab Roy</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="styles.css" />
</head>
<body>
{nav("")}
  <main id="main">
    <section class="hero research-hero">
      <div class="container research-intro">
        <p class="eyebrow">ARNAB ROY / RESEARCH NOTEBOOK</p>
        <h1>Notes on software supply-chain attacks.</h1>
        <p class="hero-copy">A personal research notebook for tracking package ecosystem incidents, affected ecosystems, exposure questions, and practical defender actions.</p>
      </div>
    </section>
    <section class="section section-border">
      <div class="container split-grid">
        <p class="section-label">LATEST</p>
        <div class="research-list">
{cards}
        </div>
      </div>
    </section>
  </main>
{footer("")}
"""
    RESEARCH_PAGE.write_text(page, encoding="utf-8")


def render_sitemap(state: dict[str, Any]) -> None:
    urls = [
        ("https://arnabroy24.github.io/", local_today()),
        ("https://arnabroy24.github.io/research.html", local_today()),
    ]
    for incident in state.get("incidents", {}).values():
        if incident.get("published") and incident.get("post_path"):
            urls.append((f"https://arnabroy24.github.io/{incident['post_path']}", incident_lastmod_date(incident)))
    entries = "\n".join(
        f"  <url><loc>{html.escape(url)}</loc><lastmod>{html.escape(lastmod)}</lastmod></url>" for url, lastmod in urls
    )
    (ROOT / "sitemap.xml").write_text(f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n{entries}\n</urlset>\n', encoding="utf-8")
    (ROOT / "robots.txt").write_text("User-agent: *\nAllow: /\nSitemap: https://arnabroy24.github.io/sitemap.xml\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lookback-days", type=int, default=int(os.environ.get("LOOKBACK_DAYS", "21")))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    args = parser.parse_args()

    state = load_json(STATE_PATH, {"version": 1, "incidents": {}, "last_run_at": None})
    migrate_incident_dates(state)
    POSTS_DIR.mkdir(parents=True, exist_ok=True)

    items = fetch_all_feeds()
    cutoff = now_utc() - dt.timedelta(days=args.lookback_days)
    relevant = [
        item
        for item in items
        if date_from_iso(item["published_at"]) >= cutoff and looks_relevant(item)
    ]
    relevant = [enrich_with_article_text(item) for item in relevant]
    print(f"relevant feed items: {len(relevant)}", file=sys.stderr)

    changed_slugs: set[str] = set()
    for item in sorted(relevant, key=lambda entry: entry["published_at"]):
        slug, changed = ensure_incident(item, state)
        if changed:
            changed_slugs.add(slug)

    api_key = os.environ.get("OPENAI_API_KEY", "")
    if changed_slugs and not api_key and not args.dry_run:
        raise SystemExit("OPENAI_API_KEY is required when new or updated incidents need synthesis.")

    for slug in sorted(changed_slugs):
        incident = state["incidents"][slug]
        if args.dry_run:
            print(f"would synthesize: {slug}", file=sys.stderr)
            continue
        article = synthesize_article(incident, api_key, args.model)
        if not article.get("should_publish"):
            incident["published"] = False
            incident["skipped_at"] = iso_now()
            continue
        render_post(slug, incident, article)

    state["last_run_at"] = iso_now()
    if not args.dry_run:
        patch_existing_post_dates(state)
        write_json(STATE_PATH, state)
        render_research_page(state)
        render_sitemap(state)
    else:
        print(json.dumps({"changed_slugs": sorted(changed_slugs)}, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
