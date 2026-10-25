import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import '../crypto/hardened_crypto_engine.dart';
import '../../features/chat/domain/secure_message.dart';

typedef OnPacketReceived = void Function(NetworkPacket packet);

/// Client Réseau Résilient & Durci pour Réseau Mobile (4G / 5G / Wi-Fi Public)
/// - Authentification cryptographique obligatoire (Ed25519) sur chaque requête POLL
/// - Reconnexion avec backoff exponentiel et gigue (jitter) pour gérer les coupures réseau cellulaires
/// - Timeouts stricts et fail-secure (zéro fuite de données)
class HardenedRelayClient {
  static const String defaultTunnelUrl =
      "https://zero-trust-messenger.onrender.com";

  final String relayBaseUrl;
  final String myMailbox;
  final String myDeviceId;
  final SimpleKeyPair mySigningKeyPair;
  final OnPacketReceived onPacketReceived;

  Timer? _pollingTimer;
  bool _isPolling = false;
  int _consecutiveFailures = 0;
  final HttpClient _httpClient = HttpClient();

  HardenedRelayClient({
    this.relayBaseUrl = defaultTunnelUrl,
    required this.myMailbox,
    required this.myDeviceId,
    required this.mySigningKeyPair,
    required this.onPacketReceived,
  }) {
    // Timeout strict pour éviter le gel sur réseau mobile instable
    _httpClient.connectionTimeout = const Duration(seconds: 8);
  }

  void start() {
    _pollingTimer?.cancel();
    _scheduleNextPoll(Duration.zero);
  }

  void stop() {
    _pollingTimer?.cancel();
    _pollingTimer = null;
    _httpClient.close(force: true);
  }

  void _scheduleNextPoll(Duration delay) {
    _pollingTimer = Timer(delay, () async {
      await _executeSignedPoll();
      
      // Calcul du délai avec backoff exponentiel et gigue (Jitter)
      final int baseIntervalMs = 1200;
      final int backoffMs = min(baseIntervalMs * pow(1.5, _consecutiveFailures).toInt(), 15000);
      final int jitter = Random().nextInt(400);
      _scheduleNextPoll(Duration(milliseconds: backoffMs + jitter));
    });
  }

  /// Exécute une récupération de paquets avec preuve de possession Ed25519
  Future<void> _executeSignedPoll() async {
    if (_isPolling) return;
    _isPolling = true;

    try {
      final int timestamp = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final String challengeData = "POLL:$myMailbox:$timestamp";

      // 1. Signature cryptographique de la requête
      final String signature = await HardenedCryptoEngine.instance.signData(
        signingKey: mySigningKeyPair,
        data: challengeData,
      );

      final pubKey = await mySigningKeyPair.extractPublicKey();
      final pubKeyB64 = base64Url.encode(pubKey.bytes);

      // 2. Requête HTTPS vers le serveur relais distant
      final uri = Uri.parse("$relayBaseUrl/api/v2/relay/poll");
      final request = await _httpClient.postUrl(uri);
      request.headers.contentType = ContentType.json;
      
      final requestBody = jsonEncode({
        'mailbox': myMailbox,
        'public_key': pubKeyB64,
        'timestamp': timestamp,
        'signature': signature,
      });

      request.write(requestBody);
      final response = await request.close().timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        _consecutiveFailures = 0;
        final responseString = await response.transform(utf8.decoder).join();
        final Map<String, dynamic> data = jsonDecode(responseString);
        final List<dynamic> packets = data['packets'] as List<dynamic>? ?? [];

        for (final p in packets) {
          try {
            final packet = NetworkPacket.fromJson(p as Map<String, dynamic>);
            onPacketReceived(packet);
          } catch (_) {}
        }
      } else {
        _consecutiveFailures++;
      }
    } catch (_) {
      _consecutiveFailures++;
    } finally {
      _isPolling = false;
    }
  }

  /// Envoi d'un paquet chiffré vers le relais distant via le réseau mobile
  Future<bool> sendEncryptedPacket(NetworkPacket packet) async {
    try {
      final uri = Uri.parse("$relayBaseUrl/api/v2/relay/send");
      final request = await _httpClient.postUrl(uri);
      request.headers.contentType = ContentType.json;

      final body = jsonEncode({
        'target_mailbox': packet.targetMailbox,
        'packet': packet.toJson(),
      });

      request.write(body);
      final response = await request.close().timeout(const Duration(seconds: 10));
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }
}
