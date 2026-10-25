import 'dart:convert';
import 'dart:typed_data';

class Contact {
  final String id;
  final String alias;
  final Uint8List dhPublicKey;
  final Uint8List signPublicKey;
  final String mailbox;
  final DateTime addedAt;

  Contact({
    required this.id,
    required this.alias,
    required this.dhPublicKey,
    required this.signPublicKey,
    required this.mailbox,
    required this.addedAt,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'alias': alias,
    'dhPublicKey': base64Url.encode(dhPublicKey),
    'signPublicKey': base64Url.encode(signPublicKey),
    'mailbox': mailbox,
    'addedAt': addedAt.toIso8601String(),
  };

  factory Contact.fromJson(Map<String, dynamic> json) => Contact(
    id: json['id'] as String,
    alias: json['alias'] as String,
    dhPublicKey: base64Url.decode(json['dhPublicKey']),
    signPublicKey: base64Url.decode(json['signPublicKey']),
    mailbox: json['mailbox'] as String,
    addedAt: DateTime.parse(json['addedAt'] as String),
  );
}
