"""The scanner's daily digest: every security issue found in one run, in one email to tech@.

Security issues never fail the run; a failed run means the scanner itself broke (including the
digest failing to send), which Render's failure notification covers. Nothing is emailed on a day
with no issues.
"""
import json, os, urllib.error, urllib.request
from datetime import date

SMTP2GO = "https://api.smtp2go.com/v3/email/send"
TO = os.environ.get("DIGEST_TO", "tech@commonknowledge.coop")
SENDER = os.environ.get("DIGEST_FROM", "CK Security Scanner <security-scanner@commonknowledge.coop>")


def render(sections, notes=()):
    """Plain-text digest from {section title: [issue lines]}; empty sections are left out."""
    total = sum(len(v) for v in sections.values())
    out = [f"{total} security issue{'s' if total != 1 else ''} found by the security scanner on {date.today():%A %-d %B %Y}.", ""]
    for title, lines in sections.items():
        if lines:
            out += [f"{title} ({len(lines)})", "-" * (len(title) + len(str(len(lines))) + 3)] + [f"- {l}" for l in lines] + [""]
    if notes:
        out += ["Notes", "-----"] + [f"- {n}" for n in notes] + [""]
    out.append("Sent by the security-scanner cron job on Render (github.com/commonknowledge/security-scanner).")
    return total, "\n".join(out)


def send(sections, notes=(), api_key=None):
    """Print the digest, and email it if there's anything in it. Raises if the email can't be sent."""
    total, body = render(sections, notes)
    print(body)
    if not total:
        print("No security issues, so no digest emailed")
        return
    if not api_key:
        print("Digest not emailed: SMTP2GO_API_KEY is not set")
        return
    subject = f"Security scanner: {total} issue{'s' if total != 1 else ''} ({date.today():%-d %b})"
    req = urllib.request.Request(SMTP2GO, data=json.dumps({"sender": SENDER, "to": [TO], "subject": subject,
                                                           "text_body": body}).encode(),
                                 headers={"Content-Type": "application/json", "Accept": "application/json",
                                          "X-Smtp2go-Api-Key": api_key, "User-Agent": "ck-security-scanner"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            result = json.load(r)
    except urllib.error.HTTPError as err:
        raise RuntimeError(f"SMTP2GO {err.code}: {err.read().decode()[:300]}") from err
    if not result.get("data", {}).get("succeeded"):
        raise RuntimeError(f"SMTP2GO didn't send the digest: {result}")
    print(f"Digest emailed to {TO}")
