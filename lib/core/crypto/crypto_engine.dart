import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

class CryptoEngine {
  static final CryptoEngine instance = CryptoEngine._internal();
  CryptoEngine._internal();

  final X25519 _x25519 = X25519();
  final Ed25519 _ed25519 = Ed25519();
  final AesGcm _aesGcm = AesGcm.with256bits();
  final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  // 1. Génération de clés Diffie-Hellman pour le chiffrement
  Future<KeyPair> generateDhKeyPair() async => await _x25519.newKeyPair();

  // 2. Génération de clés de signature d'identité
  Future<SimpleKeyPair> generateSigningKeyPair() async => await _ed25519.newKeyPair();

  // 3. Extraction d'octets d'une clé publique
  Future<Uint8List> exportPublicKeyBytes(PublicKey key) async {
    return Uint8List.fromList((key as SimplePublicKey).bytes);
  }

  // 4. Signature cryptographique du payload QR
  Future<String> signData({
    required SimpleKeyPair signingKey,
    required String data,
  }) async {
    final signature = await _ed25519.sign(
      utf8.encode(data),
      keyPair: signingKey,
    );
    return base64Url.encode(signature.bytes);
  }

  // 5. Vérification de signature Ed25519
  Future<bool> verifySignature({
    required Uint8List publicKeyBytes,
    required String data,
    required String signatureBase64,
  }) async {
    try {
      final sigBytes = base64Url.decode(signatureBase64);
      final pubKey = SimplePublicKey(publicKeyBytes, type: KeyPairType.ed25519);
      final signature = Signature(sigBytes, publicKey: pubKey);
      return await _ed25519.verify(utf8.encode(data), signature: signature);
    } catch (_) {
      return false;
    }
  }

  // 6. Chiffrement hybride E2EE avec Perfect Forward Secrecy (PFS)
  Future<EncryptedEnvelope> encryptMessage({
    required Uint8List recipientDhPubKeyBytes,
    required String plaintext,
  }) async {
    // Génération clé éphémère à usage unique
    final ephemeralKeyPair = await _x25519.newKeyPair();
    final ephemeralPubKey = await ephemeralKeyPair.extractPublicKey();

    // Accord Diffie-Hellman
    final recipientPubKey = SimplePublicKey(recipientDhPubKeyBytes, type: KeyPairType.x25519);
    final sharedSecret = await _x25519.sharedSecretKey(
      keyPair: ephemeralKeyPair,
      remotePublicKey: recipientPubKey,
    );

    // KDF pour générer la clé de session AES-256
    final sessionKey = await _hkdf.deriveKey(
      secretKey: sharedSecret,
      nonce: utf8.encode("ZERO-TRUST-NONCE-SALT"),
      info: utf8.encode("E2EE-ZERO-TRUST-MESSAGE-V1"),
    );

    // Chiffrement AES-GCM
    final nonce = _aesGcm.newNonce();
    final secretBox = await _aesGcm.encrypt(
      utf8.encode(plaintext),
      secretKey: sessionKey,
      nonce: nonce,
    );

    return EncryptedEnvelope(
      ephemeralPublicKey: Uint8List.fromList(ephemeralPubKey.bytes),
      nonce: Uint8List.fromList(secretBox.nonce),
      cipherText: Uint8List.fromList(secretBox.cipherText),
      macTag: Uint8List.fromList(secretBox.mac.bytes),
    );
  }

  // 7. Déchiffrement E2EE
  Future<String> decryptMessage({
    required KeyPair myDhKeyPair,
    required EncryptedEnvelope envelope,
  }) async {
    final senderEphemeralPubKey = SimplePublicKey(
      envelope.ephemeralPublicKey,
      type: KeyPairType.x25519,
    );

    final sharedSecret = await _x25519.sharedSecretKey(
      keyPair: myDhKeyPair,
      remotePublicKey: senderEphemeralPubKey,
    );

    final sessionKey = await _hkdf.deriveKey(
      secretKey: sharedSecret,
      nonce: utf8.encode("ZERO-TRUST-NONCE-SALT"),
      info: utf8.encode("E2EE-ZERO-TRUST-MESSAGE-V1"),
    );

    final secretBox = SecretBox(
      envelope.cipherText,
      nonce: envelope.nonce,
      mac: Mac(envelope.macTag),
    );

    final decryptedBytes = await _aesGcm.decrypt(
      secretBox,
      secretKey: sessionKey,
    );

    return utf8.decode(decryptedBytes);
  }
}

class EncryptedEnvelope {
  final Uint8List ephemeralPublicKey;
  final Uint8List nonce;
  final Uint8List cipherText;
  final Uint8List macTag;

  EncryptedEnvelope({
    required this.ephemeralPublicKey,
    required this.nonce,
    required this.cipherText,
    required this.macTag,
  });

  Map<String, dynamic> toJson() => {
    'eph_pk': base64Url.encode(ephemeralPublicKey),
    'nonce': base64Url.encode(nonce),
    'ct': base64Url.encode(cipherText),
    'tag': base64Url.encode(macTag),
  };

  factory EncryptedEnvelope.fromJson(Map<String, dynamic> json) => EncryptedEnvelope(
    ephemeralPublicKey: base64Url.decode(json['eph_pk']),
    nonce: base64Url.decode(json['nonce']),
    cipherText: base64Url.decode(json['ct']),
    macTag: base64Url.decode(json['tag']),
  );
}
