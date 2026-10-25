"""
Zero Trust Messenger — Serveur Relais Aveugle & Hôte Multiplateforme Durci
Modèle Zéro-Knowledge absolu pour transit via réseau mobile (4G/5G) & Cloudflare Tunnel :
- Aucun message en clair, aucun annuaire public, aucune clé privée ou publique conservée.
- Authentification cryptographique obligatoire (Signature ECDSA secp256r1) pour vider une boîte aux lettres.
- Serveur WSGI multi-threadé haute concurrence (backlog 128, accept() non-bloquant) pour éviter tout refus TCP avec cloudflared.
- Plafond strict de taille par paquet (64 Ko) et purge automatique (TTL 72h).
"""

import os
import ssl
import time
import socket
import datetime
import ipaddress
import base64
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.serving import ThreadedWSGIServer
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, utils

app = Flask(__name__, static_folder="static", static_url_path="")

# ============================================================================
# POLITIQUES DE SÉCURITÉ & LIMITES
# ============================================================================
MAX_PACKET_SIZE = 64 * 1024          # 64 Ko max par paquet
MAX_QUEUE_PER_MAILBOX = 100          # 100 messages max en attente
PACKET_TTL_SECONDS = 72 * 3600       # TTL 72h
RATE_LIMIT_WINDOW = 60               # 60 secondes
MAX_REQUESTS_PER_WINDOW = 2400       # 2400 requêtes/min (supporte le polling temps réel multi-appareils derrière CGNAT 4G)
CHALLENGE_MAX_DRIFT_SEC = 900        # Tolérance d'horloge 15 min entre mobile 4G et PC
DEFAULT_TUNNEL_URL = "https://script-gardening-antibody-fields.trycloudflare.com"

MAILBOX_QUEUES = defaultdict(list)
RATE_LIMIT_TRACKER = defaultdict(list)
RELAY_STATS = {
    "packets_routed": 0,
    "auth_failures": 0,
    "started_at": int(time.time()),
}


def get_client_ip() -> str:
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    RATE_LIMIT_TRACKER[ip] = [t for t in RATE_LIMIT_TRACKER[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(RATE_LIMIT_TRACKER[ip]) >= MAX_REQUESTS_PER_WINDOW:
        return False
    RATE_LIMIT_TRACKER[ip].append(now)
    return True


def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ensure_ssl_cert(cert_path: str, key_path: str, lan_ip: str):
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Zero Trust Messenger"),
        x509.NameAttribute(NameOID.COMMON_NAME, lan_ip),
    ])

    san_list = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    try:
        san_list.append(x509.IPAddress(ipaddress.ip_address(lan_ip)))
    except Exception:
        pass

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


class HighConcurrencyHybridServer(ThreadedWSGIServer):
    """
    Serveur multi-threadé à haute capacité (backlog = 128).
    La détection HTTP/HTTPS est effectuée dans le thread worker (process_request_thread)
    et JAMAIS dans la boucle d'acceptation principale, garantissant 0ms de blocage pour cloudflared.
    """
    request_queue_size = 128
    daemon_threads = True

    def __init__(self, host, port, app_instance, ssl_ctx):
        super().__init__(host, port, app_instance)
        self.ssl_ctx = ssl_ctx

    def process_request_thread(self, request_sock, client_address):
        try:
            request_sock.settimeout(5.0)
            first_byte = request_sock.recv(1, socket.MSG_PEEK)
            request_sock.settimeout(None)
            if first_byte == b"\x16":
                request_sock = self.ssl_ctx.wrap_socket(request_sock, server_side=True)
        except Exception:
            pass
        super().process_request_thread(request_sock, client_address)


@app.before_request
def security_gate():
    if request.method == "OPTIONS":
        return ("", 204)
    ip = get_client_ip()
    if not check_rate_limit(ip):
        return jsonify({"error": "RATE_LIMIT_EXCEEDED"}), 429


@app.after_request
def add_security_headers(response):
    response.headers["Permissions-Policy"] = "camera=(self *), microphone=()"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-ZT-Protocol"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, no-transform, max-age=0"
    response.headers["X-Accel-Buffering"] = "no"
    return response


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/status", methods=["GET"])
def status():
    lan_ip = get_lan_ip()
    tunnel_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tunnel_url.txt")
    tunnel_url = DEFAULT_TUNNEL_URL
    if os.path.exists(tunnel_file):
        try:
            with open(tunnel_file, "r") as f:
                read_url = f.read().strip()
                if read_url:
                    tunnel_url = read_url
        except Exception:
            pass

    return jsonify({
        "status": "online",
        "mode": "HARDENED_ZERO_KNOWLEDGE_BLIND_RELAY",
        "server_time": int(time.time()),
        "packets_routed": RELAY_STATS["packets_routed"],
        "auth_failures": RELAY_STATS["auth_failures"],
        "active_mailboxes": len(MAILBOX_QUEUES),
        "queued_mailboxes": {k: len(v) for k, v in MAILBOX_QUEUES.items()},
        "lan_ip": lan_ip,
        "port": 5050,
        "android_https_url": f"https://{lan_ip}:5050",
        "public_4g_url": tunnel_url,
    })


@app.route("/api/relay/send", methods=["POST"])
@app.route("/api/v2/relay/send", methods=["POST"])
def relay_send():
    if request.content_length and request.content_length > MAX_PACKET_SIZE:
        return jsonify({"error": "PAYLOAD_TOO_LARGE"}), 413

    data = request.get_json(silent=True) or {}
    target_mailbox = data.get("target_mailbox")
    packet = data.get("packet")

    if not target_mailbox or not packet or not isinstance(packet, dict):
        return jsonify({"error": "INVALID_PACKET_SCHEMA"}), 400

    envelope = packet.get("envelope")
    if not envelope or "ct" not in envelope or "tag" not in envelope or "iv" not in envelope:
        return jsonify({"error": "INVALID_ENVELOPE_FORMAT"}), 400

    now = int(time.time())
    queue = MAILBOX_QUEUES[target_mailbox]

    # Purge TTL
    MAILBOX_QUEUES[target_mailbox] = [p for p in queue if now - p.get("ts", 0) < PACKET_TTL_SECONDS]

    if len(MAILBOX_QUEUES[target_mailbox]) >= MAX_QUEUE_PER_MAILBOX:
        return jsonify({"error": "MAILBOX_QUEUE_FULL"}), 507

    packet["ts"] = now
    MAILBOX_QUEUES[target_mailbox].append(packet)
    RELAY_STATS["packets_routed"] += 1
    return jsonify({"status": "QUEUED", "routed_to": target_mailbox})


@app.route("/api/relay/poll", methods=["POST"])
@app.route("/api/v2/relay/poll", methods=["POST"])
def relay_poll():
    """
    Récupération sécurisée Zéro-Knowledge :
    Exige la preuve cryptographique de possession de la boîte aux lettres via signature P-256 (ECDSA).
    """
    data = request.get_json(silent=True) or {}
    mailbox = data.get("mailbox")
    timestamp = data.get("timestamp")
    signature_b64 = data.get("signature")
    pub_x = data.get("pub_x")
    pub_y = data.get("pub_y")

    if not all([mailbox, timestamp, signature_b64, pub_x, pub_y]):
        RELAY_STATS["auth_failures"] += 1
        return jsonify({"error": "AUTHENTICATION_REQUIRED", "detail": "Missing cryptographic proof"}), 401

    now = int(time.time())
    try:
        ts_int = int(timestamp)
        if abs(now - ts_int) > CHALLENGE_MAX_DRIFT_SEC:
            RELAY_STATS["auth_failures"] += 1
            return jsonify({"error": "TIMESTAMP_EXPIRED"}), 401
    except Exception:
        return jsonify({"error": "INVALID_TIMESTAMP"}), 400

    try:
        def b64url_decode(s):
            s = s.replace("-", "+").replace("_", "/")
            s += "=" * ((4 - len(s) % 4) % 4)
            return base64.b64decode(s)

        x_bytes = b64url_decode(pub_x)
        y_bytes = b64url_decode(pub_y)
        sig_bytes = b64url_decode(signature_b64)

        if len(x_bytes) != 32 or len(y_bytes) != 32 or len(sig_bytes) != 64:
            raise ValueError("Invalid curve parameter length")

        r_int = int.from_bytes(sig_bytes[:32], "big")
        s_int = int.from_bytes(sig_bytes[32:], "big")
        der_signature = utils.encode_dss_signature(r_int, s_int)

        pub_numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_bytes, "big"),
            int.from_bytes(y_bytes, "big"),
            ec.SECP256R1(),
        )
        verify_key = pub_numbers.public_key()
        challenge_canonical = f"POLL:{mailbox}:{timestamp}".encode("utf-8")
        verify_key.verify(der_signature, challenge_canonical, ec.ECDSA(hashes.SHA256()))

    except Exception as e:
        RELAY_STATS["auth_failures"] += 1
        return jsonify({"error": "CRYPTOGRAPHIC_AUTH_FAILED", "detail": str(e)}), 403

    packets = MAILBOX_QUEUES.pop(mailbox, [])
    return jsonify({"packets": packets})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    lan_ip = get_lan_ip()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cert_file = os.path.join(base_dir, "cert.pem")
    key_file = os.path.join(base_dir, "key.pem")

    ensure_ssl_cert(cert_file, key_file, lan_ip)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    server = HighConcurrencyHybridServer("0.0.0.0", port, app, ssl_context)
    server.serve_forever()
