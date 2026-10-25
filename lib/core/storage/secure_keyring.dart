import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import '../../features/chat/domain/contact.dart';

class SecureKeyring {
  static final SecureKeyring instance = SecureKeyring._internal();
  SecureKeyring._internal();

  final FlutterSecureStorage _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    mOptions: MacOsOptions(accessibility: KeychainAccessibility.first_unlock),
    wOptions: WindowsOptions(useBackwardCompatibility: false),
  );

  static const _keyMyDeviceId = "zt_my_device_id";
  static const _keyMyAlias = "zt_my_alias";
  static const _keyMyMailbox = "zt_my_mailbox";
  static const _keyDhPriv = "zt_dh_priv";
  static const _keyDhPub = "zt_dh_pub";
  static const _keySignPriv = "zt_sign_priv";
  static const _keySignPub = "zt_sign_pub";
  static const _keyContactsPrefix = "zt_contact_";

  Future<void> saveIdentity({
    required String deviceId,
    required String alias,
    required String mailbox,
    required String dhPrivB64,
    required String dhPubB64,
    required String signPrivB64,
    required String signPubB64,
  }) async {
    await _storage.write(key: _keyMyDeviceId, value: deviceId);
    await _storage.write(key: _keyMyAlias, value: alias);
    await _storage.write(key: _keyMyMailbox, value: mailbox);
    await _storage.write(key: _keyDhPriv, value: dhPrivB64);
    await _storage.write(key: _keyDhPub, value: dhPubB64);
    await _storage.write(key: _keySignPriv, value: signPrivB64);
    await _storage.write(key: _keySignPub, value: signPubB64);
  }

  Future<Map<String, String?>> getIdentity() async {
    return {
      'deviceId': await _storage.read(key: _keyMyDeviceId),
      'alias': await _storage.read(key: _keyMyAlias),
      'mailbox': await _storage.read(key: _keyMyMailbox),
      'dhPriv': await _storage.read(key: _keyDhPriv),
      'dhPub': await _storage.read(key: _keyDhPub),
      'signPriv': await _storage.read(key: _keySignPriv),
      'signPub': await _storage.read(key: _keySignPub),
    };
  }

  Future<void> saveVerifiedContact(Contact contact) async {
    final key = "$_keyContactsPrefix${contact.id}";
    await _storage.write(key: key, value: jsonEncode(contact.toJson()));
  }

  Future<List<Contact>> getVerifiedContacts() async {
    final all = await _storage.readAll();
    final List<Contact> contacts = [];
    for (final entry in all.entries) {
      if (entry.key.startsWith(_keyContactsPrefix)) {
        try {
          final data = jsonDecode(entry.value);
          contacts.add(Contact.fromJson(data));
        } catch (_) {}
      }
    }
    return contacts;
  }

  Future<bool> isContactWhitelisted(String deviceId) async {
    final data = await _storage.read(key: "$_keyContactsPrefix$deviceId");
    return data != null;
  }
}
