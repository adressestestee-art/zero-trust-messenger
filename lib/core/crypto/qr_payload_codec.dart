import 'dart:convert';
import 'dart:typed_data';
import 'crypto_engine.dart';

class QrPayload {
  final int version;
  final String deviceId;
  final String alias;
  final Uint8List dhPublicKey;
  final Uint8List signPublicKey;
  final String mailbox;
  final int timestamp;
  final String signature;

  QrPayload({
    required this.version,
    required this.deviceId,
    required this.alias,
    required this.dhPublicKey,
    required this.signPublicKey,
    required this.mailbox,
    required this.timestamp,
    required this.signature,
  });

  String get canonicalData =>
      "$version|$deviceId|$alias|${base64Url.encode(dhPublicKey)}|${base64Url.encode(signPublicKey)}|$mailbox|$timestamp";

  String serialize() {
    final map = {
      'v': version,
      'id': deviceId,
      'alias': alias,
      'pk_dh': base64Url.encode(dhPublicKey),
      'pk_sign': base64Url.encode(signPublicKey),
      'mb': mailbox,
      'ts': timestamp,
      'sig': signature,
    };
    return base64Url.encode(utf8.encode(jsonEncode(map)));
  }

  static Future<QrPayload?> deserializeAndVerify(String rawQrContent) async {
    try {
      final jsonStr = utf8.decode(base64Url.decode(rawQrContent.trim()));
      final Map<String, dynamic> map = jsonDecode(jsonStr);

      final payload = QrPayload(
        version: map['v'] as int,
        deviceId: map['id'] as String,
        alias: map['alias'] as String,
        dhPublicKey: base64Url.decode(map['pk_dh']),
        signPublicKey: base64Url.decode(map['pk_sign']),
        mailbox: map['mb'] as String,
        timestamp: map['ts'] as int,
        signature: map['sig'] as String,
      );

      final isValid = await CryptoEngine.instance.verifySignature(
        publicKeyBytes: payload.signPublicKey,
        data: payload.canonicalData,
        signatureBase64: payload.signature,
      );

      return isValid ? payload : null;
    } catch (_) {
      return null;
    }
  }
}
