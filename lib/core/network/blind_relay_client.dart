import 'dart:async';
import 'dart:convert';
import 'package:web_socket_channel/web_socket_channel.dart';
import '../../features/chat/domain/secure_message.dart';

typedef OnPacketReceived = void Function(NetworkPacket packet);

class BlindRelayClient {
  final String serverUrl;
  final String myMailbox;
  WebSocketChannel? _channel;
  StreamSubscription? _subscription;
  final OnPacketReceived onPacketReceived;

  BlindRelayClient({
    required this.serverUrl,
    required this.myMailbox,
    required this.onPacketReceived,
  });

  void connect() {
    try {
      _channel = WebSocketChannel.connect(Uri.parse(serverUrl));
      
      // Enregistrement de notre boîte aux lettres aveugle auprès du relais
      final registerMsg = jsonEncode({
        'action': 'register',
        'mailbox': myMailbox,
      });
      _channel!.sink.add(registerMsg);

      _subscription = _channel!.stream.listen(
        (data) {
          try {
            final map = jsonDecode(data as String);
            if (map['action'] == 'message') {
              final packet = NetworkPacket.fromJson(map['packet']);
              onPacketReceived(packet);
            }
          } catch (_) {}
        },
        onError: (err) {},
        onDone: () {},
      );
    } catch (_) {}
  }

  void sendPacket(NetworkPacket packet) {
    if (_channel != null) {
      final msg = jsonEncode({
        'action': 'forward',
        'packet': packet.toJson(),
      });
      _channel!.sink.add(msg);
    }
  }

  void disconnect() {
    _subscription?.cancel();
    _channel?.sink.close();
  }
}
