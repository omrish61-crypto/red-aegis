"""Burp Suite extractor — sitemap XML export.

Sitemap structure:
  <sitemap>
    <host name="http://host:port" ip="10.0.0.5">
      <url><url>http://host:port/path</url><params><param name="id">...</param></params></url>
    </host>
  </sitemap>
Facts: path (endpoint URLs), param (extracted parameters).
"""

import xml.etree.ElementTree as ET

from .common import bounded, dedupe_facts


def extract(text: str):
    facts = []
    warnings = []
    text = text.strip()
    if not text:
        return [], []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return [], [f"burp sitemap parse failed: {exc}"]
    host_name = None
    for host in root.iter("host"):
        host_name = host.get("name")
        for url_el in host.iter("url"):
            url_text = ""
            for u in url_el.iter("url"):
                url_text = (u.text or "").strip()
                break
            if url_text:
                facts.append({"fact_type": "path",
                              "value": {"path": bounded(url_text),
                                        "host": host_name or ""}})
            for param in url_el.iter("param"):
                pname = param.get("name")
                if pname:
                    facts.append({"fact_type": "param",
                                  "value": {"param": pname, "host": host_name or ""}})
    return dedupe_facts(facts), warnings
