import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:file_picker/file_picker.dart';
import '../../../core/crypto/qr_payload_codec.dart';
import '../../../core/theme/app_theme.dart';

class UniversalQrScannerScreen extends StatefulWidget {
  final Function(QrPayload payload) onContactVerified;

  const UniversalQrScannerScreen({super.key, required this.onContactVerified});

  @override
  State<UniversalQrScannerScreen> createState() => _UniversalQrScannerScreenState();
}

class _UniversalQrScannerScreenState extends State<UniversalQrScannerScreen> {
  final MobileScannerController _scannerController = MobileScannerController(
    detectionSpeed: DetectionSpeed.normal,
    facing: CameraFacing.back,
  );

  bool _isProcessing = false;
  String? _errorMessage;

  void _onDetect(BarcodeCapture capture) async {
    if (_isProcessing) return;
    for (final barcode in capture.barcodes) {
      final code = barcode.rawValue;
      if (code != null) {
        await _processRawPayload(code);
        break;
      }
    }
  }

  Future<void> _processRawPayload(String rawCode) async {
    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    final payload = await QrPayload.deserializeAndVerify(rawCode);

    if (!mounted) return;

    if (payload != null) {
      Navigator.of(context).pop();
      widget.onContactVerified(payload);
    } else {
      setState(() {
        _isProcessing = false;
        _errorMessage = "Échec : Signature cryptographique falsifiée ou QR invalide.";
      });
    }
  }

  Future<void> _pickImageFile() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['png', 'jpg', 'jpeg', 'webp'],
      );

      if (result != null && result.files.single.path != null) {
        final filePath = result.files.single.path!;
        final barcode = await _scannerController.analyzeImage(filePath);
        if (barcode != null && barcode.barcodes.isNotEmpty) {
          final code = barcode.barcodes.first.rawValue;
          if (code != null) {
            await _processRawPayload(code);
            return;
          }
        }
        setState(() {
          _errorMessage = "Aucun QR code valide détecté dans l'image sélectionnée.";
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = "Erreur lors de la lecture du fichier : $e";
      });
    }
  }

  @override
  void dispose() {
    _scannerController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isDesktop = !kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux);

    return Scaffold(
      backgroundColor: AppTheme.pureBlack,
      appBar: AppBar(
        title: const Text("SCANNER CONTACT ZERO TRUST"),
        actions: [
          if (isDesktop)
            Padding(
              padding: const EdgeInsets.only(right: 8.0),
              child: TextButton.icon(
                icon: const Icon(Icons.file_upload_outlined, color: AppTheme.cyberGreen, size: 18),
                label: const Text(
                  "Importer Fichier",
                  style: TextStyle(color: AppTheme.cyberGreen, fontSize: 13, fontWeight: FontWeight.bold),
                ),
                onPressed: _pickImageFile,
              ),
            ),
        ],
      ),
      body: Stack(
        alignment: Alignment.center,
        children: [
          // 1. Flux vidéo caméra / webcam
          MobileScanner(
            controller: _scannerController,
            onDetect: _onDetect,
          ),

          // 2. Réticule Cyber / Sécurité
          Container(
            width: 270,
            height: 270,
            decoration: BoxDecoration(
              border: Border.all(color: AppTheme.cyberGreen, width: 2),
              borderRadius: BorderRadius.circular(16),
              boxShadow: [
                BoxShadow(
                  color: AppTheme.cyberGreen.withOpacity(0.25),
                  blurRadius: 25,
                  spreadRadius: 2,
                )
              ],
            ),
            child: const Center(
              child: Icon(Icons.center_focus_strong, color: AppTheme.cyberGreen, size: 40),
            ),
          ),

          // 3. Status & Instructions
          Positioned(
            bottom: 40,
            left: 20,
            right: 20,
            child: Column(
              children: [
                if (_errorMessage != null)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                    margin: const EdgeInsets.only(bottom: 14),
                    decoration: BoxDecoration(
                      color: AppTheme.alertRed.withOpacity(0.85),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(
                      _errorMessage!,
                      style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold),
                      textAlign: TextAlign.center,
                    ),
                  ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  decoration: BoxDecoration(
                    color: Colors.black.withOpacity(0.7),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(color: Colors.white12),
                  ),
                  child: Text(
                    isDesktop
                        ? "Orientez la webcam vers le QR code ou cliquez sur 'Importer Fichier'."
                        : "Alignez le QR code du contact physique dans le cadre.",
                    style: const TextStyle(color: Colors.white70, fontSize: 12),
                    textAlign: TextAlign.center,
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
