import os
import json
import socket
import subprocess
from pathlib import Path

from flask import Flask, jsonify, render_template, request

try:
    import shodan
except ImportError:
    shodan = None

app = Flask(__name__)

def get_api_key():
    # Prefer an environment variable. Otherwise use the key saved by `shodan init`.
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if key:
        return key
    config_path = Path.home() / ".shodan" / "api_key"
    try:
        return config_path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""

def get_api():
    if shodan is None:
        raise RuntimeError("The Shodan Python package is not installed in this environment.")
    key = get_api_key()
    if not key:
        raise RuntimeError("No API key found. Run `shodan init YOUR_NEW_API_KEY` in your activated shodan-venv.")
    return shodan.Shodan(key)

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/status")
def status():
    try:
        api = get_api()
        info = api.info()
        return jsonify({
            "ok": True,
            "plan": info.get("plan", "Unknown"),
            "query_credits": info.get("query_credits", 0),
            "scan_credits": info.get("scan_credits", 0),
            "monitored_ips": info.get("monitored_ips", 0),
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

@app.post("/api/search")
def search():
    body = request.get_json(silent=True) or {}
    query = str(body.get("query", "")).strip()
    if not query:
        return jsonify({"error": "Enter a Shodan search query."}), 400
    if len(query) > 300:
        return jsonify({"error": "Query is too long."}), 400
    try:
        limit = int(body.get("limit", 10))
        limit = max(1, min(limit, 50))
        api = get_api()
        result = api.search(query, page=1)
        matches = []
        for item in result.get("matches", [])[:limit]:
            location = item.get("location") or {}
            matches.append({
                "ip": item.get("ip_str", "Unknown"),
                "port": item.get("port", "?"),
                "org": item.get("org") or item.get("isp") or "Unknown",
                "country": location.get("country_name") or "Unknown",
                "city": location.get("city") or "",
                "product": item.get("product") or item.get("http", {}).get("server") or "Unknown service",
                "hostnames": item.get("hostnames") or [],
                "domains": item.get("domains") or [],
                "timestamp": item.get("timestamp") or "",
                "transport": item.get("transport") or "",
            })
        return jsonify({
            "query": query,
            "total": result.get("total", len(matches)),
            "matches": matches,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

@app.post("/api/host")
def host_lookup():
    body = request.get_json(silent=True) or {}
    ip = str(body.get("ip", "")).strip()
    if not ip or len(ip) > 100:
        return jsonify({"error": "Enter a valid IP address or hostname."}), 400
    try:
        result = get_api().host(ip)
        return jsonify({
            "ip": result.get("ip_str", ip),
            "organization": result.get("org") or result.get("isp") or "Unknown",
            "country": (result.get("country_name") or "Unknown"),
            "os": result.get("os") or "Unknown",
            "hostnames": result.get("hostnames") or [],
            "ports": result.get("ports") or [],
            "tags": result.get("tags") or [],
            "vulns": sorted(list((result.get("vulns") or {}).keys())),
            "services": [
                {
                    "port": d.get("port"),
                    "transport": d.get("transport"),
                    "product": d.get("product") or d.get("http", {}).get("server") or "Unknown",
                    "version": d.get("version") or "",
                    "banner": (d.get("data") or "")[:700],
                }
                for d in (result.get("data") or [])[:30]
            ],
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


def spiderfoot_running():
    try:
        with socket.create_connection(("127.0.0.1", 5001), timeout=1):
            return True
    except OSError:
        return False

@app.get("/api/spiderfoot/status")
def spiderfoot_status():
    return jsonify({"running": spiderfoot_running()})

@app.post("/api/spiderfoot/start")
def spiderfoot_start():
    if spiderfoot_running():
        return jsonify({"ok": True, "message": "SpiderFoot is already running."})

    try:
        log_path = Path.home() / ".jarvis-spiderfoot.log"
        log = open(log_path, "a", encoding="utf-8")
        subprocess.Popen(
            ["/usr/bin/spiderfoot", "-l", "127.0.0.1:5001"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
        log.close()
        return jsonify({
            "ok": True,
            "message": "SpiderFoot startup requested."
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500



@app.get("/shodan")
def stark_shodan_page():
    return render_template("shodan.html")


@app.get("/spiderfoot")
def stark_spiderfoot_page():
    return render_template("spiderfoot.html")


@app.get("/sherlock")
def stark_sherlock_page():
    return render_template("sherlock.html")


@app.post("/api/sherlock/search")
def sherlock_search():
    import re

    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", username):
        return jsonify({
            "ok": False,
            "error": "Enter a username using letters, numbers, dots, underscores, or hyphens (max 40 characters)."
        }), 400

    try:
        result = subprocess.run(
            ["/usr/bin/sherlock", "--print-found", "--no-color",
             "--no-txt", username],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        output = ((result.stdout or "") + (result.stderr or ""))[-30000:]
        return jsonify({
            "ok": result.returncode == 0,
            "username": username,
            "output": output,
            "error": "" if result.returncode == 0 else "Sherlock returned a non-zero exit status."
        })
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Search timed out. Try again."}), 504
    except OSError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


def phoneinfoga_running():
    import socket
    try:
        with socket.create_connection(("127.0.0.1", 5002), timeout=1):
            return True
    except OSError:
        return False


@app.post("/api/phoneinfoga/start")
def phoneinfoga_start():
    if phoneinfoga_running():
        return jsonify({"ok": True, "message": "PhoneInfoga is already running."})
    import shutil
    import os
    import subprocess
    from pathlib import Path

    binary = shutil.which("phoneinfoga") or "/usr/local/bin/phoneinfoga"
    if not Path(binary).is_file():
        return jsonify({"ok": False, "error": "PhoneInfoga binary was not found."}), 500
    try:
        log = open(Path.home() / ".jarvis-phoneinfoga.log", "a", encoding="utf-8")
        subprocess.Popen(
            [binary, "serve", "--port", "5002"],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True,
        )
        log.close()
        return jsonify({"ok": True, "message": "PhoneInfoga startup requested on local port 5002."})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.get("/phoneinfoga")
def stark_phoneinfoga_page():
    return render_template("phoneinfoga.html")


@app.post("/api/phoneinfoga/scan")
def phoneinfoga_scan():
    import re
    import shutil
    import subprocess

    body = request.get_json(silent=True) or {}
    raw_number = str(body.get("number", "")).strip()

    # Accept common formatting, then normalize to international digits.
    if not raw_number or not re.fullmatch(r"[+0-9().\s-]{5,30}", raw_number):
        return jsonify({
            "ok": False,
            "error": "Enter a phone number in international format, such as +1 202 555 0123."
        }), 400

    digits = re.sub(r"\D", "", raw_number)
    if not raw_number.lstrip().startswith("+") or not 8 <= len(digits) <= 15 or digits.startswith("0"):
        return jsonify({
            "ok": False,
            "error": "Use a complete international number beginning with +, with 8–15 digits. +1 alone is not a complete number."
        }), 400

    number = "+" + digits
    binary = shutil.which("phoneinfoga") or "/usr/local/bin/phoneinfoga"

    try:
        result = subprocess.run(
            [binary, "scan", "-n", number],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        return jsonify({
            "ok": result.returncode == 0,
            "number": number,
            "output": output[-30000:],
            "error": "" if result.returncode == 0 else
                "PhoneInfoga finished with an error. Review the output below."
        }), 200
    except subprocess.TimeoutExpired:
        return jsonify({
            "ok": False,
            "error": "The scan timed out after 180 seconds. Try again later."
        }), 504
    except OSError as exc:
        return jsonify({
            "ok": False,
            "error": "Could not launch PhoneInfoga: " + str(exc)
        }), 500


# ===== JARVIS RECON-NG CONTROL CENTER =====
@app.get("/reconng")
def stark_reconng_page():
    return render_template("reconng.html")


@app.post("/api/reconng/command")
def reconng_command():
    import re
    import shutil

    body = request.get_json(silent=True) or {}
    action = str(body.get("action", "")).strip()
    workspace = str(body.get("workspace", "default")).strip()
    term = str(body.get("term", "")).strip()

    # Restrict workspace names to simple identifiers.
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", workspace):
        return jsonify({"ok": False, "error": "Workspace names may contain letters, numbers, _ and - only."}), 400

    binary = shutil.which("recon-cli") or "/usr/bin/recon-cli"
    if not Path(binary).is_file():
        return jsonify({"ok": False, "error": "recon-cli was not found. Install Recon-ng first."}), 500

    commands = {
        "help": "help",
        "dashboard": "dashboard",
        "show_modules": "show modules",
        "show_workspaces": "workspaces list",
        "list_keys": "keys list",
        "show_domains": "show domains",
        "show_hosts": "show hosts",
        "show_contacts": "show contacts",
        "show_companies": "show companies",
        "show_ports": "show ports",
        "show_vulnerabilities": "show vulnerabilities",
        "show_credentials": "show credentials",
        "show_locations": "show locations",
        "show_profiles": "show profiles",
        "show_repositories": "show repositories",
        "show_schema": "show schema",
        "module_search": None,
    }

    if action not in commands:
        return jsonify({"ok": False, "error": "That command button is not supported."}), 400

    command = commands[action]
    if action == "module_search":
        if not term or len(term) > 100 or not re.fullmatch(r"[A-Za-z0-9_./ -]+", term):
            return jsonify({"ok": False, "error": "Enter a module search term using letters, numbers, spaces, /, . _ or -."}), 400
        command = "modules search " + term

    args = [
        binary, "-w", workspace,
        "-C", command,
        "--no-marketplace", "--no-analytics", "--no-version",
    ]

    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=45, check=False
        )
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        return jsonify({
            "ok": result.returncode == 0,
            "action": action,
            "workspace": workspace,
            "command": command,
            "output": output[-25000:] or "(No output returned.)",
            "returncode": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Recon-ng timed out after 45 seconds."}), 504
    except OSError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

# JARVIS BBOT control center


# JARVIS Evilginx build-status page only. This does not launch Evilginx.

# LAB_DOMAIN_MANAGER_ROUTES
LAB_DOMAINS_FILE = Path.home() / "jarvis_shodan_ui" / "data" / "lab_domains.json"

def read_lab_domains():
    try:
        data = json.loads(LAB_DOMAINS_FILE.read_text())
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []

def valid_lab_domain(value):
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or "." not in value:
        return None
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+", value):
        return None
    return value

@app.get("/domains")
def lab_domains_page():
    return render_template("domains.html")

@app.get("/api/lab-domains")
def lab_domains_list():
    return jsonify({"ok": True, "domains": read_lab_domains()})

@app.post("/api/lab-domains")
def lab_domains_add():
    body = request.get_json(silent=True) or {}
    domain = valid_lab_domain(str(body.get("domain", "")))
    if not domain:
        return jsonify({"ok": False, "error": "Enter a valid domain name."}), 400
    domains = read_lab_domains()
    if any(item.get("domain") == domain for item in domains):
        return jsonify({"ok": False, "error": "That domain is already listed."}), 409
    domains.append({"domain": domain, "note": str(body.get("note", ""))[:200]})
    LAB_DOMAINS_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAB_DOMAINS_FILE.write_text(json.dumps(domains, indent=2) + "\n")
    return jsonify({"ok": True, "domains": domains}), 201

@app.delete("/api/lab-domains")
def lab_domains_remove():
    body = request.get_json(silent=True) or {}
    domain = valid_lab_domain(str(body.get("domain", "")))
    if not domain:
        return jsonify({"ok": False, "error": "Invalid domain."}), 400
    domains = [item for item in read_lab_domains() if item.get("domain") != domain]
    LAB_DOMAINS_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAB_DOMAINS_FILE.write_text(json.dumps(domains, indent=2) + "\n")
    return jsonify({"ok": True, "domains": domains})

@app.post("/api/lab-domains/check")
def lab_domains_check():
    body = request.get_json(silent=True) or {}
    domain = valid_lab_domain(str(body.get("domain", "")))
    if not domain or not any(item.get("domain") == domain for item in read_lab_domains()):
        return jsonify({"ok": False, "error": "Add the domain to your lab inventory first."}), 400
    try:
        results = sorted({entry[4][0] for entry in socket.getaddrinfo(domain, None)})
        return jsonify({"ok": True, "domain": domain, "addresses": results})
    except socket.gaierror as exc:
        return jsonify({"ok": False, "domain": domain, "error": str(exc), "addresses": []}), 200

@app.get("/evilginx")
def evilginx_page():
    return render_template("evilginx.html")

@app.get("/api/evilginx/status")
def evilginx_status():
    import hashlib
    import subprocess

    root = Path.home() / "security-tools" / "evilginx3-audit"
    binary = root / "build" / "evilginx"

    if not binary.is_file() or not os.access(binary, os.X_OK):
        return jsonify({
            "ok": False,
            "status": "Binary not found",
            "commit": None,
            "sha256": None
        }), 404

    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=3, check=True
        ).stdout.strip()
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        return jsonify({
            "ok": True,
            "status": "Built; not launched",
            "commit": commit,
            "sha256": digest,
            "binary_exists": True,
            "binary_path": str(binary),
            "running": False
        })
    except (OSError, subprocess.SubprocessError) as exc:
        return jsonify({
            "ok": False,
            "status": "Status check failed",
            "error": str(exc)
        }), 500



# EVILGINX_READONLY_DIAGNOSTICS
@app.get("/api/evilginx/inspect")
def evilginx_inspect():
    root = Path.home() / "security-tools" / "evilginx3-audit"
    if not root.is_dir():
        return jsonify({"ok": False, "error": "Project directory not found."}), 404
    allowed = {".yaml", ".yml", ".json", ".toml", ".md", ".go", ".mod", ".sum"}
    files = []
    for item in root.iterdir():
        if item.is_file() and item.suffix.lower() in allowed:
            files.append(item.name)
    return jsonify({"ok": True, "files": sorted(files)})

@app.get("/api/evilginx/logs")
def evilginx_logs():
    log = Path.home() / "shodan-log.log"
    try:
        lines = log.read_text(errors="replace").splitlines()[-35:]
        safe = []
        import re
        for line in lines:
            line = re.sub(r'(?i)(api[_-]?key|token|password|secret)=\\S+', r'\\1=[REDACTED]', line)
            safe.append(line[:500])
        return jsonify({"ok": True, "lines": "\\n".join(safe)})
    except OSError:
        return jsonify({"ok": True, "lines": "No dashboard log file found."})

@app.route("/bbot")
def stark_bbot_page():
    return render_template("bbot.html")

@app.route("/api/bbot/status")
def bbot_status():
    import shutil
    path = shutil.which("bbot")
    if not path:
        return jsonify({"error": "BBOT executable not found. Install BBOT and restart Flask."}), 503
    return jsonify({"output": f"BBOT executable: {path}"})

@app.route("/api/bbot/scan", methods=["POST"])
def bbot_scan():
    import re, shutil
    data = request.get_json(silent=True) or {}
    target = str(data.get("target", "")).strip()
    preset = str(data.get("preset", "subdomain-enum"))
    if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", target):
        return jsonify({"error": "Enter a valid domain or IP target."}), 400
    if ".." in target or any(part.startswith("-") for part in target.split(".")):
        return jsonify({"error": "Invalid target format."}), 400
    presets = {
        "subdomain-enum": "subdomain-enum",
        "passive": "passive",
        "safe": "safe"
    }
    if preset not in presets:
        return jsonify({"error": "Unsupported scan preset."}), 400
    executable = shutil.which("bbot")
    if not executable:
        return jsonify({"error": "BBOT executable not found. Install BBOT and restart Flask."}), 503
    import os, subprocess
    env = os.environ.copy()
    try:
        result = subprocess.run(
            [executable, "-t", target, "-p", presets[preset], "--json"],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.expanduser("~")
        )
        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        if not output.strip():
            output = f"BBOT exited with code {result.returncode} and produced no output."
        return jsonify({"output": output[-18000:], "returncode": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan exceeded the 15-minute limit. Check BBOT output and processes."}), 504
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500



@app.route("/nuclei")
def stark_nuclei_page():
    return render_template("nuclei.html")


@app.get("/api/nuclei/status")
def nuclei_status():
    import shutil
    executable = shutil.which("nuclei")
    if not executable:
        return jsonify({"error": "Nuclei executable not found."}), 503
    templates = Path.home() / ".local" / "nuclei-templates"
    count = sum(1 for _ in templates.rglob("*.yaml")) if templates.is_dir() else 0
    return jsonify({"output": f"Nuclei executable: {executable}\nTemplates found: {count}\nScan mode: conservative"})


@app.post("/api/nuclei/scan")
def nuclei_scan():
    import ipaddress
    import re
    import shutil
    import urllib.parse

    data = request.get_json(silent=True) or {}
    target = str(data.get("target", "")).strip()
    if not target or len(target) > 2048 or any(ch.isspace() for ch in target):
        return jsonify({"error": "Enter one valid domain, IP address, or HTTP(S) URL."}), 400

    candidate = target if "://" in target else "https://" + target
    try:
        parsed = urllib.parse.urlsplit(candidate)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError()
        if parsed.username or parsed.password:
            raise ValueError()
        host = parsed.hostname.rstrip(".")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not re.fullmatch(
                r"(?i)(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*",
                host
            ):
                raise ValueError()
        normalized = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path or "", parsed.query, "")
        )
    except ValueError:
        return jsonify({"error": "Invalid target. Enter a domain, IP address, or HTTP(S) URL without credentials."}), 400

    executable = shutil.which("nuclei")
    if not executable:
        return jsonify({"error": "Nuclei executable not found."}), 503

    templates = Path.home() / ".local" / "nuclei-templates"
    if not templates.is_dir() or not any(templates.rglob("*.yaml")):
        return jsonify({"error": "No YAML templates found in ~/.local/nuclei-templates. Install or update the Nuclei templates first."}), 503

    try:
        result = subprocess.run(
            [
                executable, "-u", normalized,
                "-t", str(templates),
                "-severity", "info,low,medium,high,critical",
                "-rl", "2", "-c", "2",
                "-timeout", "5", "-retries", "0",
                "-duc", "-no-color"
            ],
            capture_output=True, text=True, timeout=120,
            cwd=str(Path.home())
        )
        output = (result.stdout or "")
        if result.stderr:
            output += ("\n" if output else "") + result.stderr
        if not output.strip():
            output = f"Nuclei exited with code {result.returncode} and produced no output."
        return jsonify({"output": output[-18000:], "returncode": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan reached the 2-minute time limit. Try again later or check the target."}), 504
    except Exception:
        app.logger.exception("Nuclei scan failed")
        return jsonify({"error": "Nuclei scan failed. Check the Flask terminal logs."}), 500



@app.route("/sqlmap")
def stark_sqlmap_page():
    return render_template("sqlmap.html")


@app.get("/api/sqlmap/status")
def sqlmap_status():
    import shutil
    executable = shutil.which("sqlmap")
    if not executable:
        return jsonify({"error": "SQLmap executable not found."}), 503
    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True, text=True, timeout=10
        )
        version = (result.stdout or result.stderr).strip()
        if result.returncode != 0:
            return jsonify({"error": "SQLmap returned an error: " + version[:500]}), 503
        return jsonify({"output": f"SQLmap executable: {executable}\\nVersion: {version}\\nMode: status and URL validation only"})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "SQLmap version check timed out."}), 504
    except Exception:
        app.logger.exception("SQLmap status check failed")
        return jsonify({"error": "Could not check SQLmap. See Flask logs."}), 500


@app.get("/api/caido/status")
def caido_status():
    import shutil
    import subprocess
    import urllib.request

    cli = "/usr/lib/caido/resources/bin/caido-cli"
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=2) as r:
            return jsonify({"online": r.status == 200, "url": "http://127.0.0.1:8080"})
    except Exception:
        pass

    # Start the local-only UI/proxy service if it is not already healthy.
    if Path(cli).is_file() and shutil.which("pgrep"):
        try:
            running = subprocess.run(
                ["pgrep", "-f", r"caido-cli.*127\.0\.0\.1:8080"],
                capture_output=True, text=True
            ).returncode == 0
            if not running:
                subprocess.Popen(
                    [cli, "--listen", "127.0.0.1:8080",
                     "--data-path", str(Path.home() / ".local/share/caido-jarvis"),
                     "--no-open"],
                    stdin=subprocess.DEVNULL,
                    stdout=open(Path.home() / "caido-jarvis.log", "a"),
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )
        except Exception:
            pass

    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=4) as r:
            online = r.status == 200
    except Exception:
        online = False
    return jsonify({"online": online, "url": "http://127.0.0.1:8080"}), (200 if online else 503)


def ensure_bloodhound_running():
    """Start BloodHound only when its Compose stack is not fully running."""
    import subprocess

    compose_file = "/home/gojo/bloodhound-ce/docker-compose.yml"
    try:
        check = subprocess.run(
            ["docker", "compose", "-f", compose_file,
             "ps", "--status", "running", "-q"],
            capture_output=True, text=True, timeout=10
        )
        running_ids = [line for line in check.stdout.splitlines() if line.strip()]

        # This stack has three services: BloodHound, PostgreSQL, and Neo4j.
        if check.returncode == 0 and len(running_ids) >= 3:
            print("[JARVIS] BloodHound is already running.")
            return

        print("[JARVIS] Starting BloodHound Compose stack...")
        result = subprocess.run(
            ["docker", "compose", "-f", compose_file, "up", "-d"],
            capture_output=True, text=True, timeout=180
        )
        if result.returncode == 0:
            print("[JARVIS] BloodHound startup command completed.")
        else:
            print("[JARVIS] BloodHound startup failed:", result.stderr.strip())
    except Exception as exc:
        print(f"[JARVIS] BloodHound startup check failed: {exc}")


if __name__ == "__main__":
    ensure_bloodhound_running()
    # Keep the development server local to this machine.
    app.run(host="127.0.0.1", port=5050, debug=False)
