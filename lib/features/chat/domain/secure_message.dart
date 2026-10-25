import '../../crypto/crypto_engine.dart';

class SecureMessage {
  final String id;
  final String senderId;
  final String recipientId;
  final String text;
  final DateTime timestamp;
  final bool isFromMe;

  SecureMessage({
    required this.id,
    required this.senderId,
    required this.recipientId,
    required this.text,
    required this.timestamp,
    required this.isFromMe,
  });
}

class NetworkPacket {
  final String targetMailbox;
  final String senderDeviceId;
  final EncryptedEnvelope envelope;

  NetworkPacket({
    required this.targetMailbox,
    required this.senderDeviceId,
    required this.envelope,
  });

  Map<String, dynamic> toJson() => {
    'target_mailbox': targetMailbox,
    'sender_device_id': senderDeviceId,
    'envelope': envelope.toJson(),
  };

  factory NetworkPacket.fromJson(Map<String, dynamic> json) => NetworkPacket(
    targetMailbox: json['target_mailbox'] as String,
    senderDeviceId: json['sender_device_id'] as String,
    envelope: EncryptedEnvelope.fromJson(json['envelope'] as Map<String, dynamic>),
  );
}
