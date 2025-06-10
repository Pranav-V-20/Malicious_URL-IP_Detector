# 🔍 Malicious URL/IP Detector

A Python tool to detect **known malicious URLs and IP addresses** from log files or network traffic using the [VirusTotal](https://www.virustotal.com/) API. Supports **real-time monitoring** or scheduled scanning.

---

## 🚀 Features

* 🔗 Integrates with [VirusTotal API](https://developers.virustotal.com/reference/overview)
* 📁 Parses log files to extract URLs and IPs
* ⚠️ Flags malicious or suspicious entries
* 📡 Supports real-time file monitoring
* 📊 CLI support with `argparse`

---

## 📂 Sample Input

A log file like `sample.log`:

```log
192.168.1.100 - - [10/Jun/2025:12:34:56 +0530] "GET http://example.com/index.html HTTP/1.1" 200 1024
203.0.113.45 - - [10/Jun/2025:12:35:01 +0530] "POST http://malicious-site.ru/login.php HTTP/1.1" 403 512
198.51.100.23 - - [10/Jun/2025:12:35:07 +0530] "GET https://secure-login.example.org/auth HTTP/1.1" 200 768
203.0.113.12 - - [10/Jun/2025:12:35:13 +0530] "GET http://badip.site.com/payload.exe HTTP/1.1" 200 2048
GET http://phishing-link.info/reset-password HTTP/1.1 200 OK
Suspicious connection to IP: 45.77.111.222
Ping from 8.8.8.8
GET https://safe-site.net/resources HTTP/1.1 200 OK
Connection attempt from IP: 185.220.101.45
GET http://unknown1234.xyz/home HTTP/1.1 200 OK

```

---

## 🛠️ Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/your-username/malicious-url-ip-detector.git
   cd malicious-url-ip-detector
   ```

2. Install dependencies:

   ```bash
   pip install requests
   ```

3. Replace the `VT_API_KEY` in the script with your [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey):

   ```python
   VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
   ```

---

## 🧪 Usage

### One-time scan:

```bash
python malicious_detector.py sample.log
```

### Real-time monitoring:

```bash
python malicious_detector.py sample.log --watch --interval 60
```

| Argument     | Description                                |
| ------------ | ------------------------------------------ |
| `file`       | Path to the log file                       |
| `--watch`    | Enable real-time file monitoring           |
| `--interval` | Interval in seconds for real-time scanning |

---

## 📤 Output Example

```
🔗 Checking URL: http://malicious-site.ru
⚠️  Malicious: 5, Suspicious: 2

🌐 Checking IP: 185.220.101.45
⚠️  Malicious: 10, Suspicious: 1

🔗 Checking URL: http://example.com
✅ Clean
```

---

## 🔐 Notes

* Free VirusTotal accounts are limited to **4 requests/minute**. Consider adding rate limiting or delays in high-volume use.
* This tool is meant for educational or defensive security purposes only.

---

## 🙋‍♂️ Contributions

Contributions, issues, and feature requests are welcome!
Feel free to fork the repo and submit a pull request.

