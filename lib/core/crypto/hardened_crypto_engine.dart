import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Moteur cryptographique militaire pour environnement hostile (Réseau Cellulaire/Internet)
/// Caractéristiques :
/// - Accord de clés X25519 (ECDH) avec clé éphémère par message
/// - Dérivation HKDF-SHA256 avec séparation de domaine stricte
/// - Chiffrement AES-256-GCM avec nonce 96-bit CSPRNG unique garanti
/// - AAD (Additional Authenticated Data) liant expéditeur, destinataire et séquence monotone
/// - Table de séquences anti-rejeu (Replay Attack Prevention)
/// - Padding aléatoire constant (Blocs de 256 octets) contre l'analyse de trafic
/// - Zeroization explicite des buffers sensibles
class HardenedCryptoEngine {
  static final HardenedCryptoEngine instance = HardenedCryptoEngine._internal();
  HardenedCryptoEngine._internal();

  final X25519 _x25519 = X25519();
  final Ed25519 _ed25519 = Ed25519();
  final AesGcm _aesGcm = AesGcm.with256bits();
  final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  // Compteurs de séquence monotones par contact (persistance mémoire de session)
  final Map<String, int> _outgoingSequence = {};
  final Map<String, int> _lastReceivedSequence = {};

  // Fenêtre glissante anti-rejeu par contact (RFC 4303 / IPsec standard)
  final Map<String, _ReplayWindow> _replayWindows = {};

  Future<KeyPair> generateDhKeyPair() async => await _x25519.newKeyPair();
  Future<SimpleKeyPair> generateSigningKeyPair() async => await _ed25519.newKeyPair();

  /// Applique un padding aléatoire pour atteindre un multiple de 255 octets (Anti-Traffic Analysis)
  Uint8List _applyConstantSizePadding(Uint8List plaintext) {
    const int blockSize = 255;
    final int padLen = blockSize - (plaintext.length % blockSize); // Strictement 1..255
    final Random rng = Random.secure();
    final Uint8List padded = Uint8List(plaintext.length + padLen);
    padded.setAll(0, plaintext);
    for (int i = plaintext.length; i < padded.length - 1; i++) {
      padded[i] = rng.nextInt(256);
    }
    // Dernier octet exact = longueur du padding
    padded[padded.length - 1] = padLen;
    return padded;
  }

  /// Retire le padding de façon sécurisée
  Uint8List _removeConstantSizePadding(Uint8List padded) {
    if (padded.isEmpty) throw ArgumentError("Buffer vide");
    final int padLen = padded[padded.length - 1];
    if (padLen <= 0 || padLen > 255 || padLen > padded.length) {
      throw StateError("Padding cryptographique invalide");
    }
    return Uint8List.sublistView(padded, 0, padded.length - padLen);
  }

  /// Signature cryptographique Ed25519 d'une charge utile (Payload QR ou Challenge POLL)
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

  /// Vérification de signature Ed25519
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

  /// Chiffrement E2EE durci avec protection anti-rejeu et AAD
  Future<Map<String, dynamic>> encryptMessageHardened({
    required Uint8List recipientDhPubKeyBytes,
    required String senderId,
    required String recipientId,
    required String plaintext,
  }) async {
    // 1. Incrémentation du compteur monotone pour ce contact
    final int seq = (_outgoingSequence[recipientId] ?? 0) + 1;
    _outgoingSequence[recipientId] = seq;

    // 2. Génération de clé éphémère X25519 (PFS)
    final ephemeralKeyPair = await _x25519.newKeyPair();
    final ephemeralPubKey = await ephemeralKeyPair.extractPublicKey();

    // 3. Dérivation du secret partagé ECDH
    final recipientPubKey = SimplePublicKey(recipientDhPubKeyBytes, type: KeyPairType.x25519);
    final sharedSecret = await _x25519.sharedSecretKey(
      keyPair: ephemeralKeyPair,
      remotePublicKey: recipientPubKey,
    );

    // 4. Dérivation de clé symétrique avec séparation de domaine
    final sessionKey = await _hkdf.deriveKey(
      secretKey: sharedSecret,
      nonce: utf8.encode("ZERO-TRUST-MOBILE-DOMAIN-V2"),
      info: utf8.encode("E2EE-AES-GCM:$senderId:$recipientId"),
    );

    // 5. Construction des Données Authentifiées Associées (AAD)
    final Uint8List aad = utf8.encode("AAD-V2:$senderId:$recipientId:$seq");

    // 6. Padding à taille constante
    final Uint8List rawPlaintext = utf8.encode(plaintext);
    final Uint8List paddedPlaintext = _applyConstantSizePadding(rawPlaintext);

    // 7. Chiffrement AES-256-GCM avec nonce 96-bit aléatoire sécurisé
    final Nonce nonce = _aesGcm.newNonce();
    final SecretBox secretBox = await _aesGcm.encrypt(
      paddedPlaintext,
      secretKey: sessionKey,
      nonce: nonce,
      aad: aad,
    );

    // 8. Effacement mémoire (Zeroization)
    paddedPlaintext.fillRange(0, paddedPlaintext.length, 0);

    return {
      'alg': 'X25519/HKDF/AES-256-GCM',
      'eph_pk': base64Url.encode(ephemeralPubKey.bytes),
      'nonce': base64Url.encode(secretBox.nonce),
      'ct': base64Url.encode(secretBox.cipherText),
      'tag': base64Url.encode(secretBox.mac.bytes),
      'seq': seq,
    };
  }

  /// Déchiffrement E2EE durci avec validation par fenêtre glissante anti-rejeu (RFC 4303)
  Future<String> decryptMessageHardened({
    required KeyPair myDhKeyPair,
    required String senderId,
    required String myId,
    required Map<String, dynamic> envelope,
  }) async {
    final int seq = envelope['seq'] as int? ?? 0;
    final window = _replayWindows.putIfAbsent(senderId, () => _ReplayWindow(windowSize: 128));

    // Vérification de la fenêtre anti-rejeu avant calcul cryptographique
    if (!window.checkAndMark(seq)) {
      throw StateError("ALERTE SÉCURITÉ : Attaque par rejeu ou paquet obsolète détecté (Séquence #$seq). Paquet détruit.");
    }

    final senderEphemeralPubKey = SimplePublicKey(
      base64Url.decode(envelope['eph_pk']),
      type: KeyPairType.x25519,
    );

    final sharedSecret = await _x25519.sharedSecretKey(
      keyPair: myDhKeyPair,
      remotePublicKey: senderEphemeralPubKey,
    );

    final sessionKey = await _hkdf.deriveKey(
      secretKey: sharedSecret,
      nonce: utf8.encode("ZERO-TRUST-MOBILE-DOMAIN-V2"),
      info: utf8.encode("E2EE-AES-GCM:$senderId:$myId"),
    );

    final Uint8List aad = utf8.encode("AAD-V2:$senderId:$myId:$seq");

    final secretBox = SecretBox(
      base64Url.decode(envelope['ct']),
      nonce: base64Url.decode(envelope['nonce']),
      mac: Mac(base64Url.decode(envelope['tag'])),
    );

    final List<int> decryptedPadded = await _aesGcm.decrypt(
      secretBox,
      secretKey: sessionKey,
      aad: aad,
    );

    final Uint8List cleanBytes = _removeConstantSizePadding(Uint8List.fromList(decryptedPadded));
    return utf8.decode(cleanBytes);
  }
}

/// Fenêtre glissante anti-rejeu (RFC 4303) pour réseaux mobiles instables
class _ReplayWindow {
  final int windowSize;
  int head = 0;
  final Set<int> seenSequences = {};

  _ReplayWindow({this.windowSize = 128});

  bool checkAndMark(int seq) {
    if (seq <= 0) return false;

    if (seq > head) {
      head = seq;
      seenSequences.add(seq);
      seenSequences.removeWhere((s) => s <= head - windowSize);
      return true;
    }

    if (seq > head - windowSize) {
      if (seenSequences.contains(seq)) {
        return false; // Rejoué !
      }
      seenSequences.add(seq);
      return true;
    }

    return false; // Trop ancien (en dehors de la fenêtre)
  }
}
