"""
Real-time, traffic-based XSS-vulnerability detector
for mitmproxy (https://mitmproxy.org)

author : <you>
date   : 2025-06-18
"""

from __future__ import annotations
import re, html, urllib.parse, json
from mitmproxy import http, ctx
from typing import Dict, List

# ---------- helpers ---------------------------------------------------------

# Dangerous patterns that could indicate XSS
DANGEROUS_CHARS = {
    # Special characters that could break contexts
    '"', "'", '`', '<', '>',
    # Patterns that could introduce event handlers
    ' on', "'on", '"on'
}

HTML_ENTITY_RE    = re.compile(r"&(#\d+;|#x[0-9a-fA-F]+;|\w+;)")
URL_ENC_RE         = re.compile(r"%[0-9a-fA-F]{2}")
UNICODE_ESC_RE     = re.compile(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}")
JS_STRING_OPENERS  = ("'", '"', '`')

SCRIPT_CTX_RE = re.compile(
    r"""(?xs)
        # Match any HTML tag (self-closing or with attributes)
        (?P<tag_content><(?!script\b|style\b|/script\b|/style\b)[a-z][a-z0-9]*(?:\s+[^>]*?)?>)
        # Script blocks (kept separate for special handling)
      | (?P<script_block><script\b[^>]*>.*?</script>)
        # Inline event handlers (including those in attribute values)
      | (?P<event_handler>\bon\w+\s*=\s*['\"]|['\"]\s*on\w+\s*=\s*['\"])
        # Unquoted attributes (excluding href/src with URLs)
      | (?P<unquoted_attr><[^>]+?\s+[^>]*?\b(?!href\s*=|src\s*=)\w+\s*=\s*(?!['\"])(?![^>]*?\?)[^\s>]+[^>]*?>)
        # JS sinks
      | (?P<js_sink>eval\s*\(|document\.(write\(|writeln\(|createElement\s*\(.*?\)\.(innerHTML|outerHTML)\s*=)|innerHTML\s*=|outerHTML\s*=|document\.(body|documentElement)\.(inner|outer)HTML\s*=|document\.(body|documentElement)\.(insertAdjacentHTML|insertAdjacentText|insertAdjacentElement)\s*\(|document\.(body|documentElement|scripts|images|forms|links|anchors|embeds|plugins|applets|all)\[.*?\]\s*=|setTimeout\s*\(|setInterval\s*\(|Function\s*\(|setAttribute\s*\(.*?,\s*[^,]*?\s*\)|location\s*=\s*|location\.(href|pathname|search|hash|hostname|port|protocol)\s*=|window\.open\s*\(|document\.(location|URL|cookie)\s*=|importScripts\s*\(|XMLHttpRequest\(|fetch\s*\()
    """
)

STATIC_SUFFIXES = (
    ".css",".js",".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".ttf",".eot",".otf",".mp4",".webm"
)

def get_context_info(ctx_window: str, payload_start: int) -> dict:
    """Analyze the context around a potential XSS payload.
    
    Returns:
        dict: Context information including context_type and relevant positions
    """
    # Find all matches in the context window
    matches = list(SCRIPT_CTX_RE.finditer(ctx_window))
    if not matches:
        return {'context_type': 'unknown'}
    
    # Find the match that's closest to our payload
    closest_match = min(matches, 
                      key=lambda m: abs((m.start() + m.end())//2 - payload_start))
    
    context_type = next((name for name in SCRIPT_CTX_RE.groupindex 
                       if closest_match.group(name)), 'unknown')
    
    # Get the text before the payload within the context window
    before_payload = ctx_window[:payload_start]

    # Find relevant positions for attribute context analysis
    last_double_quote = before_payload.rfind('"')
    last_single_quote = before_payload.rfind("'")
    last_gt = before_payload.rfind('>')
    last_eq = before_payload.rfind('=')
    last_slash = before_payload.rfind('/')
    
    # Determine if we're in an attribute context
    in_attr_context = False
    attr_quote_type = None
    
    # Find the last tag start before the payload
    last_tag_start = before_payload.rfind('<')
    
    # Only proceed if we found a tag start
    if last_tag_start != -1:
        # Get the tag content
        tag_content = before_payload[last_tag_start:]
        
        # Check if we have an unclosed attribute
        if '=' in tag_content:
            # Get the part after the last equals sign
            after_last_eq = tag_content[tag_content.rfind('=')+1:].strip()
            
            # If there's no quote after the equals, it's an unquoted attribute
            if not after_last_eq or after_last_eq[0] not in '"\'':
                in_attr_context = True
            else:
                # Check if the quote is properly closed
                quote_char = after_last_eq[0]
                quote_content = after_last_eq[1:]
                
                # If the quote isn't closed, we're in an attribute value
                if quote_char not in quote_content:
                    in_attr_context = True
                    attr_quote_type = quote_char
        
        # Special case: check for attributes without values (boolean attributes)
        elif any(tag_content.rstrip().endswith(attr) for attr in 
                [' checked', ' disabled', ' readonly', ' required', ' selected']):
            in_attr_context = True
    
    # Debug logs
    ctx.log.warn(f"In attribute context: {in_attr_context}")
    ctx.log.warn(f"Attribute quote type: {attr_quote_type}")
    
    # Determine if we're in a script context
    in_script = '<script' in before_payload.lower() and '</script>' not in before_payload.lower()
    
    return {
        'context_type': context_type,
        'in_attr_context': in_attr_context,
        'attr_quote_type': attr_quote_type,
        'in_script': in_script,
        'match_start': closest_match.start(),
        'match_end': closest_match.end(),
        'closest_match': closest_match.group()
    }


def is_payload_dangerous(payload: str, context: dict) -> bool:
    """Determine if a payload is dangerous in the given context.
    
    Args:
        payload: The potential XSS payload
        context: Context information from get_context_info()
        
    Returns:
        bool: True if the payload is dangerous in this context
    """
    # Characters that can be dangerous in various contexts
    dangerous_html = {'<', '>', '&'}
    dangerous_attr = {'"', "'", ' ', '>', '<', '`'}
    dangerous_js = {'"', "'", '`', '\\', '(', ')', '[', ']', '{', '}', ';', '&', '<', '>'}
    
    # Check based on context type
    if context['in_attr_context'] and context['attr_quote_type']:
        # Inside a quoted attribute value
        if context['attr_quote_type'] == '"':
            # Inside double-quoted attribute - only care about unescaped double quotes
            # Single quotes are allowed without encoding in double-quoted attributes
            if '"' in payload and '&quot;' not in payload and '&#34;' not in payload:
                return True
        elif context['attr_quote_type'] == "'":
            # Inside single-quoted attribute - only care about unescaped single quotes
            # Double quotes are allowed without encoding in single-quoted attributes
            if "'" in payload and '&apos;' not in payload and '&#39;' not in payload:
                return True
    elif context['in_attr_context']:
        # Inside unquoted attribute - any special character is dangerous
        if any(c in payload for c in dangerous_attr):
            return True
    elif context['in_script']:
        # Inside script tag - any JS special character is dangerous
        if any(c in payload for c in dangerous_js):
            return True
    else:
        # In HTML context - check for HTML special characters
        if any(c in payload for c in dangerous_html):
            return True
            
    return False


def _decode_all(s: str) -> str:
    """iteratively decode html entities, url-enc & unicode escapes."""
    prev = None
    while prev != s:
        prev = s
        try:            s = html.unescape(s)
        except:         pass
        try:            s = urllib.parse.unquote_plus(s)
        except:         pass
        for m in UNICODE_ESC_RE.findall(s):
            c = chr(int(m[2:], 16))
            s = s.replace(m, c)
    return s

def _is_static(flow: http.HTTPFlow) -> bool:
    path = flow.request.path.lower()
    if any(path.endswith(s) for s in STATIC_SUFFIXES):
        return True
    ct = flow.response.headers.get("content-type","")
    if ct.startswith(("image/","font/","text/css","application/javascript")):
        return True
    cc = flow.response.headers.get("cache-control","")
    if "max-age" in cc or "immutable" in cc:
        return True
    return False

# ---------- core objects -----------------------------------------------------

class ParameterTracker:
    """store parameters with minimal retention (per request-id)"""
    def __init__(self):
        self.store : Dict[str,Dict[str,str]] = {}

    def add(self, fid: str, params: Dict[str,str]):
        self.store[fid] = params

    def pop(self, fid: str) -> Dict[str,str]:
        return self.store.pop(fid, {})

param_tracker = ParameterTracker()

# ---------- mitmproxy hooks --------------------------------------------------

def request(flow: http.HTTPFlow):
    """Inspect inbound request → extract parameters & heuristics."""
    if flow.request.host is None:
        return
    # --- classify static first (cheap) – still need params for context bypass
    parsed = urllib.parse.urlparse(flow.request.url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    body_params = {}
    if flow.request.headers.get("content-type","").startswith("application/x-www-form-urlencoded"):
        body_params = urllib.parse.parse_qs(flow.request.get_text(), keep_blank_values=True)
    cookies = flow.request.cookies
    hdr_params = {k: v for k,v in flow.request.headers.items() if k.lower().startswith("x-")}

    merged : Dict[str,str] = {}
    for d in (qs, body_params, cookies, hdr_params):
        for k, v in d.items():
            if isinstance(v, list): v = v[0]
            merged[k] = v

    if merged:
        param_tracker.add(flow.id, merged)

def response(flow: http.HTTPFlow):
    """Analyse each response against stored parameters."""
    params = param_tracker.pop(flow.id)
    if not params:  # nothing attacker-controlled
        return
    if _is_static(flow):
        return
    
    # Skip non-HTML responses
    content_type = flow.response.headers.get('content-type', '').lower()
    if 'text/html' not in content_type:
        return

    # Get the raw response content without any decoding
    try:
        response_content = flow.response.content.decode('utf-8', errors='replace')
    except Exception as e:
        ctx.log.warn(f"Failed to decode response content: {e}")
        return
    
    # --- reflection & context verifier --------------------------------------
    found = []  # List[Dict[str, str]]
    for k,v in params.items():
        # Only decode the request parameter values, not the response content
        v_norm = _decode_all(v).strip()
        if not v_norm or len(v_norm) < 10:
            continue

        ctx.log.warn(f"Checking parameter: {k}={v_norm}")
        # Phase-1: check for any dangerous patterns in the parameter value
        has_risky_construct = any(
            pattern.lower() in v_norm.lower() 
            for pattern in DANGEROUS_CHARS
        ) or SCRIPT_CTX_RE.search(v_norm)
        
        if not has_risky_construct:
            ctx.log.warn(f"Skipping parameter {k}: No risky construct found")
            continue

        # Phase-2: look for full value reflection in the response
        start = 0
        while True:
            # Search for the normalized parameter in the raw response content
            idx = response_content.find(v_norm, start)
            if idx == -1:
                break

            # Phase-3: analyse surrounding context
            ctx_window = response_content[max(0, idx-120): idx+len(v_norm)+120]
            payload_start = min(120, idx)  # position of payload in ctx_window
            ctx.log.warn(f"Found potential XSS in context: {ctx_window}")
            
            # Get context information
            context = get_context_info(ctx_window, payload_start)
            ctx.log.warn(f"Context: {context}")
            
            # Check if the payload is actually dangerous in this context
            is_dangerous = is_payload_dangerous(v_norm, context)
            ctx.log.warn(f"Is payload dangerous: {is_dangerous}")
            if not is_dangerous:
                start = idx + len(v_norm)
                continue
                
            # If we get here, the payload is potentially dangerous
            found.append({
                'param': k,
                'value': v_norm,
                'context_type': context['context_type'],
                'context_snippet': ctx_window[max(0, context['match_start']-20): 
                                           min(len(ctx_window), context['match_end']+20)]
            })

            start = idx + len(v_norm)

    if found:
        _log_finding(flow, found)

# ---------- logging ----------------------------------------------------------
# cat xss-report.log | jq -r .url | cut -d '?' -f 1 | sort -u | wc
LOGFILE = "xss-report.log"

def _log_finding(flow: http.HTTPFlow, findings: List[Dict]):
    """Write a single-line JSON record for each confirmed vuln."""
    # Safely extract request body (may not be text or may be gzipped etc.)
    try:
        body_txt = flow.request.get_text(strict=False)
    except ValueError:
        body_txt = ""

    record = {
        "url": flow.request.url,
        "method": flow.request.method,
        "time": flow.request.timestamp_start,
        "findings": findings,
        "requestHeaders": dict(flow.request.headers),
        "requestBody": body_txt[:1024],  # trim to 1 KB so the log stays small
    }

    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    ctx.log.warn(f"[XSS-VULN] {flow.request.url} ← {len(findings)} reflected param(s)")


