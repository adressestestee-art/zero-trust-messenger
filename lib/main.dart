import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:uuid/uuid.dart';
import 'core/crypto/crypto_engine.dart';
import 'core/crypto/qr_payload_codec.dart';
import 'core/storage/secure_keyring.dart';
import 'core/theme/app_theme.dart';
import 'features/chat/presentation/responsive_home.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialisation ou récupération de l'identité cryptographique Zero Trust
  final keyring = SecureKeyring.instance;
  final identity = await keyring.getIdentity();

  String deviceId = identity['deviceId'] ?? '';
  String alias = identity['alias'] ?? '';
  String mailbox = identity['mailbox'] ?? '';
  String? dhPubB64 = identity['dhPub'];
  String? signPubB64 = identity['signPub'];
  String? signPrivB64 = identity['signPriv'];

  // Premier démarrage : Génération des clés locales
  if (deviceId.isEmpty || dhPubB64 == null || signPubB64 == null || signPrivB64 == null) {
    const uuid = Uuid();
    deviceId = "zt-dev-${uuid.v4()}";
    mailbox = "mb-${uuid.v4().substring(0, 12)}";
    alias = "Agent-${deviceId.substring(7, 11).toUpperCase()}";

    // 1. Paire d'échange de clés Diffie-Hellman X25519
    final dhKeyPair = await CryptoEngine.instance.generateDhKeyPair();
    final dhPub = await dhKeyPair.extractPublicKey();
    final dhPriv = await dhKeyPair.extractPrivateKeyBytes();

    // 2. Paire de signature Ed25519
    final signKeyPair = await CryptoEngine.instance.generateSigningKeyPair();
    final signPub = await signKeyPair.extractPublicKey();
    final signPriv = await signKeyPair.extractPrivateKeyBytes();

    dhPubB64 = base64Url.encode(dhPub.bytes);
    signPubB64 = base64Url.encode(signPub.bytes);
    signPrivB64 = base64Url.encode(signPriv);

    await keyring.saveIdentity(
      deviceId: deviceId,
      alias: alias,
      mailbox: mailbox,
      dhPrivB64: base64Url.encode(dhPriv),
      dhPubB64: dhPubB64,
      signPrivB64: signPrivB64,
      signPubB64: signPubB64,
    );
  }

  // Construction du QR Payload officiel signé
  final dhPubBytes = base64Url.decode(dhPubB64);
  final signPubBytes = base64Url.decode(signPubB64);
  final ts = DateTime.now().millisecondsSinceEpoch ~/ 1000;

  final canonicalData = "1|$deviceId|$alias|${base64Url.encode(dhPubBytes)}|${base64Url.encode(signPubBytes)}|$mailbox|$ts";

  // Signature de l'identité
  final signKeyPair = await CryptoEngine.instance.generateSigningKeyPair();
  final signature = await CryptoEngine.instance.signData(
    signingKey: signKeyPair,
    data: canonicalData,
  );

  final myQrPayload = QrPayload(
    version: 1,
    deviceId: deviceId,
    alias: alias,
    dhPublicKey: dhPubBytes,
    signPublicKey: signPubBytes,
    mailbox: mailbox,
    timestamp: ts,
    signature: signature,
  );

  final myQrEncoded = myQrPayload.serialize();

  runApp(ZeroTrustMessengerApp(
    myQrPayloadEncoded: myQrEncoded,
    myAlias: alias,
    myDeviceId: deviceId,
    myMailbox: mailbox,
  ));
}

class ZeroTrustMessengerApp extends StatelessWidget {
  final String myQrPayloadEncoded;
  final String myAlias;
  final String myDeviceId;
  final String myMailbox;

  const ZeroTrustMessengerApp({
    super.key,
    required this.myQrPayloadEncoded,
    required this.myAlias,
    required this.myDeviceId,
    required this.myMailbox,
  });

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Zero Trust Messenger',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.darkTheme,
      home: ResponsiveZeroTrustHome(
        myQrPayloadEncoded: myQrPayloadEncoded,
        myAlias: myAlias,
        myDeviceId: myDeviceId,
        myMailbox: myMailbox,
      ),
    );
  }
}
