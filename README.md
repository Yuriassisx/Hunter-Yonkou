# 🔥 Hunter-Kaido
> Advanced Offensive Web Scanner for Parameter Fuzzing & Vulnerability Discovery

Hunter-Kaido é uma ferramenta ofensiva automatizada para reconhecimento, fuzzing inteligente de parâmetros e detecção de vulnerabilidades web, ideal para pentesters, red teams e bug bounty hunters.

---

## 🚀 Features
- Enumeração de subdomínios (subfinder)
- Coleta massiva de URLs (gau)
- Validação de hosts ativos
- Fuzzing inteligente de parâmetros HTTP
- Geração dinâmica de payloads
- Mutação avançada (encoding, case, WAF bypass, polyglots)
- Execução assíncrona de alta performance
- Detecção de XSS, SQLi, SSTI, SSRF, RCE e IDOR
- Sistema de priorização (Q-table)
- Rate limit por host
- Estatísticas em tempo real

---

## 🧠 Pipeline
Target → Subdomains → URLs → Alive → Param Discovery → Payload → Mutation → Fuzzing → Detection

---

## ⚙️ Instalação
### Requisitos
- Python 3.10+
- subfinder
- gau

### Dependências
pip install aiohttp

### Instalar ferramentas externas
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest  
go install github.com/lc/gau/v2/cmd/gau@latest  

export PATH=$PATH:$(go env GOPATH)/bin

---

## ▶️ Uso
python3 hunter-kaido.py target.com

---

## 📊 Output
- URLs coletadas
- Parâmetros testados
- Payloads utilizados
- Vulnerabilidades encontradas

Exemplo:
[TEST][XSS] param=q payload=<script>alert(1)</script>  
[XSS] http://target.com/search?q=<script>alert(1)</script>

---

## 🧪 Vulnerabilidades Detectadas
- XSS (reflection)
- SQLi (error-based)
- SSTI (execução {{7*7}})
- SSRF (localhost/127.0.0.1)
- RCE (uid/gid)
- IDOR (diferença de resposta)

---

## 🧬 Engine de Payload
Base:
- XSS → <script>alert(1)</script>
- SQLi → ' OR 1=1--
- SSTI → {{7*7}}
- SSRF → http://127.0.0.1
- RCE → ;id

Mutações:
- Encoding / double encoding
- Random case
- WAF bypass
- Polyglots
- Context-aware injection

---

## ⚡ Performance
- Async (asyncio + aiohttp)
- Controle de concorrência
- Rate limit por host
- Deduplicação de requests

---

## 📈 Estatísticas
[STATS]  
URLs: 1200  
Params: 340  
Requests: 5600  
Vulns: 12  

---

## ⚙️ Configuração
THREADS = 10  
RATE = 0.05  
TIMEOUT = 6  

---

## 🛡️ WAF Awareness
- Cloudflare
- Akamai
- Imperva
- Sucuri

---

## ⚠️ Aviso Legal
Uso exclusivo para ambientes autorizados (pentest, bug bounty, labs). Uso indevido pode ser ilegal.

---

## 🧠 Filosofia
Hunter-Kaido simula comportamento ofensivo real com recon, mutação adaptativa e análise de resposta.

---

## 👨‍💻 Autor
https://www.linkedin.com/in/yuri-assis-074a66200/

---

## ⭐ Contribuição
Pull requests são bem-vindos. Abra uma issue antes de mudanças maiores.
