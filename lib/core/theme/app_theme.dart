import 'package:flutter/material.dart';

class AppTheme {
  // Constantes de couleur Zero Trust Dark Mode
  static const Color pureBlack = Color(0xFF000000);
  static const Color darkSurface = Color(0xFF0A0A0A);
  static const Color cardSurface = Color(0xFF141414);
  static const Color dividerColor = Color(0xFF222222);
  
  static const Color cyberGreen = Color(0xFF00FF66);
  static const Color electricCyan = Color(0xFF00E5FF);
  static const Color alertRed = Color(0xFFFF3366);

  static ThemeData get darkTheme {
    return ThemeData(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: pureBlack,
      canvasColor: pureBlack,
      primaryColor: cyberGreen,
      colorScheme: const ColorScheme.dark(
        primary: cyberGreen,
        secondary: electricCyan,
        surface: darkSurface,
        background: pureBlack,
        error: alertRed,
        onPrimary: pureBlack,
        onSecondary: pureBlack,
        onSurface: Colors.white,
        onBackground: Colors.white,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: pureBlack,
        elevation: 0,
        centerTitle: false,
        titleTextStyle: TextStyle(
          color: cyberGreen,
          fontSize: 16,
          fontWeight: FontWeight.bold,
          letterSpacing: 1.5,
        ),
        iconTheme: IconThemeData(color: cyberGreen),
      ),
      dividerTheme: const DividerThemeData(
        color: dividerColor,
        thickness: 1,
        space: 1,
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: cardSurface,
        hintStyle: const TextStyle(color: Colors.white38, fontSize: 13),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(20),
          borderSide: BorderSide.none,
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(20),
          borderSide: const BorderSide(color: cyberGreen, width: 1),
        ),
      ),
    );
  }
}
