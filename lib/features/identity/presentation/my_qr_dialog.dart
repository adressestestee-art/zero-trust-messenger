import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../../../core/theme/app_theme.dart';

class MyQrDialog extends StatelessWidget {
  final String qrDataEncoded;
  final String myAlias;
  final String deviceId;

  const MyQrDialog({
    super.key,
    required this.qrDataEncoded,
    required this.myAlias,
    required this.deviceId,
  });

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: AppTheme.darkSurface,
      shape: RoundedRectangleBorder(
        side: const BorderSide(color: AppTheme.cyberGreen, width: 1.5),
        borderRadius: BorderRadius.circular(16),
      ),
      title: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.shield_outlined, color: AppTheme.cyberGreen, size: 20),
          const SizedBox(width: 8),
          Text(
            myAlias.toUpperCase(),
            style: const TextStyle(
              color: AppTheme.cyberGreen,
              fontSize: 15,
              fontWeight: FontWeight.bold,
              letterSpacing: 1.5,
            ),
          ),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(12),
              boxShadow: [
                BoxShadow(
                  color: AppTheme.cyberGreen.withOpacity(0.3),
                  blurRadius: 15,
                  spreadRadius: 2,
                )
              ],
            ),
            child: QrImageView(
              data: qrDataEncoded,
              version: QrVersions.auto,
              size: 230.0,
            ),
          ),
          const SizedBox(height: 16),
          Text(
            "Empreinte Matérielle : ${deviceId.substring(0, 16)}...",
            style: const TextStyle(color: Colors.white38, fontSize: 11, fontFamily: 'monospace'),
          ),
          const SizedBox(height: 10),
          const Text(
            "Faites scanner ce code en personne.\nAucune communication n'est possible sans échange optique préalable.",
            style: TextStyle(color: Colors.white70, fontSize: 12),
            textAlign: TextAlign.center,
          ),
        ],
      ),
      actions: [
        Center(
          child: TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text(
              "FERMER",
              style: TextStyle(
                color: AppTheme.cyberGreen,
                fontWeight: FontWeight.bold,
                letterSpacing: 1.2,
              ),
            ),
          ),
        ),
      ],
    );
  }
}
