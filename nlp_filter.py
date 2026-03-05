"""
V.I.G.I.L.A.N.T. - AI Content Filter
Intercepts and analyzes HTTP/HTTPS traffic.
"""
from mitmproxy import http
import spacy
import re

# Load the NLP model (sm is best for i3-6100U speed)
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("[!] Run: python -m spacy download en_core_web_sm")

# Terminology database
BRAIN_ROT_TERMS = ["skibidi", "rizz", "gyatt", "fanum tax", "sigma", "mewing"]


class VigilantFilter:
    def response(self, flow: http.HTTPFlow):
        # Only scan HTML to save CPU cycles
        if "text/html" in flow.response.headers.get("Content-Type", ""):
            text = flow.response.get_text()

            # Simple check before heavy NLP processing to save resources
            if any(term in text.lower() for term in BRAIN_ROT_TERMS):
                doc = nlp(text.lower())
                found = [t.text for t in doc if t.text in BRAIN_ROT_TERMS]

                if found:
                    print(f"[*] V.I.G.I.L.A.N.T. Blocked: {set(found)} at {flow.request.host}")

                    # Intercept and present the warning page
                    flow.response.status_code = 403
                    flow.response.set_text(
                        "<html><body style='background:#000; color:#0f0; font-family:monospace; text-align:center; padding:100px;'>"
                        "<h1>🛡️ V.I.G.I.L.A.N.T. PROTECTED 🛡️</h1>"
                        f"<p style='color:red'>Cognitive Hazard Detected: {', '.join(set(found))}</p>"
                        "<p>Access Denied by AI Gateway.</p>"
                        "</body></html>"
                    )


addons = [VigilantFilter()]