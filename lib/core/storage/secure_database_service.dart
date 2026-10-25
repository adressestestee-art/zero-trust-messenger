import 'dart:convert';
import 'dart:math';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import '../../features/chat/domain/secure_message.dart';

/// Service de Persistance Locale Ultra-Sécurisé
/// - Clé de chiffrement maître (Master DB Key 256-bit) stockée exclusivement dans le Keystore matériel de l'OS
/// - Chiffrement transparent au repos de l'historique des messages
/// - Zéro texte clair sur le disque flash (Android / macOS / Windows)
class SecureDatabaseService {
  static final SecureDatabaseService instance = SecureDatabaseService._internal();
  SecureDatabaseService._internal();

  final FlutterSecureStorage _secureVault = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    mOptions: MacOsOptions(accessibility: KeychainAccessibility.first_unlock),
    wOptions: WindowsOptions(useBackwardCompatibility: false),
  );

  static const String _keyDbMasterKey = "zt_sqlcipher_master_key_v2";
  static const String _messagesPrefix = "zt_enc_msg_";

  /// Obtient ou génère la clé cryptographique maîtresse 256-bit dans le Keystore OS
  Future<String> getOrCreateMasterDbKey() async {
    String? masterKey = await _secureVault.read(key: _keyDbMasterKey);
    if (masterKey == null) {
      final rng = Random.secure();
      final keyBytes = List<int>.generate(32, (_) => rng.nextInt(256));
      masterKey = base64Url.encode(keyBytes);
      await _secureVault.write(key: _keyDbMasterKey, value: masterKey);
    }
    return masterKey;
  }

  /// Sauvegarde d'un message avec chiffrement au repos
  Future<void> saveEncryptedMessageRecord(SecureMessage message) async {
    final recordId = "$_messagesPrefix${message.recipientId}_${message.id}";
    final serialized = jsonEncode({
      'id': message.id,
      'senderId': message.senderId,
      'recipientId': message.recipientId,
      'text': message.text,
      'ts': message.timestamp.toIso8601String(),
      'isFromMe': message.isFromMe,
    });

    // Stockage dans le coffre sécurisé de l'OS
    await _secureVault.write(key: recordId, value: serialized);
  }

  /// Chargement des messages d'un contact donné
  Future<List<SecureMessage>> loadMessagesForContact(String contactId) async {
    final all = await _secureVault.readAll();
    final List<SecureMessage> list = [];
    final prefix = "$_messagesPrefix${contactId}_";

    for (final entry in all.entries) {
      if (entry.key.startsWith(prefix)) {
        try {
          final data = jsonDecode(entry.value);
          list.add(SecureMessage(
            id: data['id'] as String,
            senderId: data['senderId'] as String,
            recipientId: data['recipientId'] as String,
            text: data['text'] as String,
            timestamp: DateTime.parse(data['ts'] as String),
            isFromMe: data['isFromMe'] as bool,
          ));
        } catch (_) {}
      }
    }

    list.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    return list;
  }
}
