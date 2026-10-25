import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../../../core/crypto/crypto_engine.dart';
import '../../../core/crypto/qr_payload_codec.dart';
import '../../../core/storage/secure_keyring.dart';
import '../../../core/theme/app_theme.dart';
import '../domain/contact.dart';
import '../domain/secure_message.dart';
import '../../identity/presentation/my_qr_dialog.dart';
import '../../scanner/presentation/universal_scanner.dart';

class ResponsiveZeroTrustHome extends StatefulWidget {
  final String myQrPayloadEncoded;
  final String myAlias;
  final String myDeviceId;
  final String myMailbox;

  const ResponsiveZeroTrustHome({
    super.key,
    required this.myQrPayloadEncoded,
    required this.myAlias,
    required this.myDeviceId,
    required this.myMailbox,
  });

  @override
  State<ResponsiveZeroTrustHome> createState() => _ResponsiveZeroTrustHomeState();
}

class _ResponsiveZeroTrustHomeState extends State<ResponsiveZeroTrustHome> {
  final List<Contact> _contacts = [];
  final Map<String, List<SecureMessage>> _messagesByContactId = {};
  Contact? _selectedContact;
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadKeyring();
  }

  Future<void> _loadKeyring() async {
    final list = await SecureKeyring.instance.getVerifiedContacts();
    setState(() {
      _contacts.clear();
      _contacts.addAll(list);
      if (_contacts.isNotEmpty && _selectedContact == null) {
        _selectedContact = _contacts.first;
      }
      _isLoading = false;
    });
  }

  void _openQrScanner() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => UniversalQrScannerScreen(
          onContactVerified: (payload) async {
            final newContact = Contact(
              id: payload.deviceId,
              alias: payload.alias,
              dhPublicKey: payload.dhPublicKey,
              signPublicKey: payload.signPublicKey,
              mailbox: payload.mailbox,
              addedAt: DateTime.now(),
            );

            await SecureKeyring.instance.saveVerifiedContact(newContact);
            setState(() {
              _contacts.removeWhere((c) => c.id == newContact.id);
              _contacts.insert(0, newContact);
              _selectedContact = newContact;
            });

            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  backgroundColor: AppTheme.darkSurface,
                  content: Row(
                    children: [
                      const Icon(Icons.check_circle, color: AppTheme.cyberGreen),
                      const SizedBox(width: 8),
                      Text("Contact cryptographique validé : ${newContact.alias}"),
                    ],
                  ),
                ),
              );
            }
          },
        ),
      ),
    );
  }

  void _openMyQrDialog() {
    showDialog(
      context: context,
      builder: (_) => MyQrDialog(
        qrDataEncoded: widget.myQrPayloadEncoded,
        myAlias: widget.myAlias,
        deviceId: widget.myDeviceId,
      ),
    );
  }

  void _sendMessage(Contact contact, String text) async {
    if (text.trim().isEmpty) return;

    // 1. Chiffrement E2EE matériel local avec la clé publique Diffie-Hellman du contact
    final envelope = await CryptoEngine.instance.encryptMessage(
      recipientDhPubKeyBytes: contact.dhPublicKey,
      plaintext: text.trim(),
    );

    // 2. Stockage local du message
    final msg = SecureMessage(
      id: DateTime.now().millisecondsSinceEpoch.toString(),
      senderId: widget.myDeviceId,
      recipientId: contact.id,
      text: text.trim(),
      timestamp: DateTime.now(),
      isFromMe: true,
    );

    setState(() {
      _messagesByContactId.putIfAbsent(contact.id, () => []).add(msg);
    });

    // Remarque : Le paquet chiffré prêt pour le serveur aveugle est ici :
    // NetworkPacket(targetMailbox: contact.mailbox, senderDeviceId: widget.myDeviceId, envelope: envelope);
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return const Scaffold(
        backgroundColor: AppTheme.pureBlack,
        body: Center(child: CircularProgressIndicator(color: AppTheme.cyberGreen)),
      );
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        final isDesktop = constraints.maxWidth >= 768;

        if (isDesktop) {
          // Layout Bureau (Windows / macOS) : Deux volets fixes
          return Scaffold(
            backgroundColor: AppTheme.pureBlack,
            body: Row(
              children: [
                SizedBox(
                  width: 320,
                  child: _buildSidebar(),
                ),
                const VerticalDivider(color: AppTheme.dividerColor, width: 1),
                Expanded(
                  child: _selectedContact != null
                      ? _buildChatPane(_selectedContact!)
                      : _buildNoChatSelectedPlaceholder(),
                ),
              ],
            ),
          );
        } else {
          // Layout Mobile (Android) : Stack Navigation
          return Scaffold(
            backgroundColor: AppTheme.pureBlack,
            appBar: AppBar(
              title: const Text("ZERO TRUST MESSENGER"),
              actions: [
                IconButton(
                  tooltip: "Mon QR Code",
                  icon: const Icon(Icons.qr_code, color: AppTheme.cyberGreen),
                  onPressed: _openMyQrDialog,
                ),
                IconButton(
                  tooltip: "Scanner un contact",
                  icon: const Icon(Icons.qr_code_scanner, color: AppTheme.cyberGreen),
                  onPressed: _openQrScanner,
                ),
              ],
            ),
            body: _buildContactsList(
              onContactSelected: (contact) {
                Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => Scaffold(
                      backgroundColor: AppTheme.pureBlack,
                      appBar: AppBar(
                        title: Row(
                          children: [
                            const Icon(Icons.verified, color: AppTheme.cyberGreen, size: 18),
                            const SizedBox(width: 8),
                            Text(contact.alias, style: const TextStyle(fontSize: 16)),
                          ],
                        ),
                      ),
                      body: _buildChatPane(contact),
                    ),
                  ),
                );
              },
            ),
          );
        }
      },
    );
  }

  Widget _buildSidebar() {
    return Column(
      children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 20),
          color: AppTheme.darkSurface,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Container(
                    width: 10,
                    height: 10,
                    decoration: const BoxDecoration(
                      color: AppTheme.cyberGreen,
                      shape: BoxShape.circle,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      widget.myAlias.toUpperCase(),
                      style: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 15,
                        letterSpacing: 1.2,
                      ),
                    ),
                  ),
                  const Icon(Icons.security, color: AppTheme.cyberGreen, size: 18),
                ],
              ),
              const SizedBox(height: 6),
              Text(
                "ID: ${widget.myDeviceId.substring(0, 18)}...",
                style: const TextStyle(color: Colors.white38, fontSize: 11, fontFamily: 'monospace'),
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      style: OutlinedButton.styleFrom(
                        side: const BorderSide(color: AppTheme.cyberGreen, width: 1),
                        foregroundColor: AppTheme.cyberGreen,
                        padding: const EdgeInsets.symmetric(vertical: 10),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                      ),
                      icon: const Icon(Icons.qr_code, size: 16),
                      label: const Text("Mon QR", style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                      onPressed: _openMyQrDialog,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: ElevatedButton.icon(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppTheme.cyberGreen,
                        foregroundColor: Colors.black,
                        padding: const EdgeInsets.symmetric(vertical: 10),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                      ),
                      icon: const Icon(Icons.qr_code_scanner, size: 16),
                      label: const Text("Scanner", style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                      onPressed: _openQrScanner,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: _buildContactsList(
            onContactSelected: (contact) {
              setState(() => _selectedContact = contact);
            },
          ),
        ),
      ],
    );
  }

  Widget _buildContactsList({required Function(Contact) onContactSelected}) {
    if (_contacts.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(30),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.shield_outlined, size: 48, color: Colors.grey.shade800),
              const SizedBox(height: 16),
              const Text(
                "AUCUN CONTACT AUTORISÉ",
                style: TextStyle(color: Colors.white60, fontWeight: FontWeight.bold, fontSize: 13, letterSpacing: 1.2),
              ),
              const SizedBox(height: 8),
              const Text(
                "Le protocole Zero Trust bloque toute communication sans échange physique de clé QR.",
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.white38, fontSize: 12),
              ),
            ],
          ),
        ),
      );
    }

    return ListView.builder(
      itemCount: _contacts.length,
      itemBuilder: (context, index) {
        final contact = _contacts[index];
        final isSelected = _selectedContact?.id == contact.id;

        return ListTile(
          tileColor: isSelected ? const Color(0xFF161616) : Colors.transparent,
          leading: Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(color: AppTheme.cyberGreen.withOpacity(0.5)),
              color: AppTheme.cardSurface,
            ),
            child: const Center(
              child: Icon(Icons.fingerprint, color: AppTheme.cyberGreen, size: 20),
            ),
          ),
          title: Text(
            contact.alias,
            style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 14),
          ),
          subtitle: Text(
            "Certifié: ${DateFormat('dd/MM/yy').format(contact.addedAt)}",
            style: const TextStyle(color: Colors.white38, fontSize: 11),
          ),
          trailing: const Icon(Icons.chevron_right, color: Colors.white24, size: 16),
          onTap: () => onContactSelected(contact),
        );
      },
    );
  }

  Widget _buildNoChatSelectedPlaceholder() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.lock_clock_outlined, size: 64, color: Colors.grey.shade900),
          const SizedBox(height: 16),
          const Text(
            "COMMUNICATION SÉCURISÉE EN ATTENTE",
            style: TextStyle(color: AppTheme.cyberGreen, letterSpacing: 2, fontWeight: FontWeight.bold, fontSize: 14),
          ),
          const SizedBox(height: 8),
          const Text(
            "Sélectionnez un contact validé ou scannez un QR code pour débuter.",
            style: TextStyle(color: Colors.white54, fontSize: 13),
          ),
        ],
      ),
    );
  }

  Widget _buildChatPane(Contact contact) {
    final textController = TextEditingController();
    final messages = _messagesByContactId[contact.id] ?? [];

    return Container(
      color: AppTheme.pureBlack,
      child: Column(
        children: [
          // Header de discussion
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
            decoration: const BoxDecoration(
              color: AppTheme.darkSurface,
              border: Border(bottom: BorderSide(color: AppTheme.dividerColor)),
            ),
            child: Row(
              children: [
                const Icon(Icons.shield, color: AppTheme.cyberGreen, size: 18),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(contact.alias, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 15)),
                      const Text(
                        "Canal E2EE Chiffré Matériellement (X25519 + AES-256-GCM + PFS)",
                        style: TextStyle(color: AppTheme.cyberGreen, fontSize: 11),
                      ),
                    ],
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: AppTheme.cyberGreen.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(color: AppTheme.cyberGreen.withOpacity(0.4)),
                  ),
                  child: const Text("ZERO TRUST VERIFIED", style: TextStyle(color: AppTheme.cyberGreen, fontSize: 10, fontWeight: FontWeight.bold)),
                ),
              ],
            ),
          ),

          // Liste des messages
          Expanded(
            child: messages.isEmpty
                ? Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.enhanced_encryption, size: 40, color: Colors.white12),
                        const SizedBox(height: 12),
                        Text(
                          "Canal vérifié avec ${contact.alias}.\nTous les messages sont chiffrés localement avant transmission.",
                          textAlign: TextAlign.center,
                          style: const TextStyle(color: Colors.white38, fontSize: 12),
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.all(16),
                    itemCount: messages.length,
                    itemBuilder: (context, index) {
                      final m = messages[index];
                      return Align(
                        alignment: m.isFromMe ? Alignment.centerRight : Alignment.centerLeft,
                        child: Container(
                          margin: const EdgeInsets.only(bottom: 10),
                          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                          decoration: BoxDecoration(
                            color: m.isFromMe ? const Color(0xFF003816) : AppTheme.cardSurface,
                            borderRadius: BorderRadius.circular(14),
                            border: Border.all(
                              color: m.isFromMe ? AppTheme.cyberGreen.withOpacity(0.4) : AppTheme.dividerColor,
                            ),
                          ),
                          child: Column(
                            crossAxisAlignment: m.isFromMe ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                            children: [
                              Text(m.text, style: const TextStyle(color: Colors.white, fontSize: 14)),
                              const SizedBox(height: 4),
                              Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Text(
                                    DateFormat('HH:mm').format(m.timestamp),
                                    style: const TextStyle(color: Colors.white38, fontSize: 10),
                                  ),
                                  if (m.isFromMe) ...[
                                    const SizedBox(width: 4),
                                    const Icon(Icons.done_all, size: 12, color: AppTheme.cyberGreen),
                                  ],
                                ],
                              ),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
          ),

          // Zone d'écriture
          Container(
            padding: const EdgeInsets.all(14),
            decoration: const BoxDecoration(
              color: AppTheme.darkSurface,
              border: Border(top: BorderSide(color: AppTheme.dividerColor)),
            ),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: textController,
                    style: const TextStyle(color: Colors.white),
                    decoration: InputDecoration(
                      hintText: "Saisir un message chiffré de bout en bout...",
                      suffixIcon: IconButton(
                        icon: const Icon(Icons.send_rounded, color: AppTheme.cyberGreen),
                        onPressed: () {
                          _sendMessage(contact, textController.text);
                          textController.clear();
                        },
                      ),
                    ),
                    onSubmitted: (val) {
                      _sendMessage(contact, val);
                      textController.clear();
                    },
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
