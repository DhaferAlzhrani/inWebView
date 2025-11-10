// import 'dart:convert';
// import 'package:flutter/material.dart';
// import 'package:flutter_inappwebview/flutter_inappwebview.dart';

// void main() {
//   WidgetsFlutterBinding.ensureInitialized();
//   runApp(const MyApp());
// }

// class MyApp extends StatelessWidget {
//   const MyApp({super.key});

//   @override
//   Widget build(BuildContext context) {
//     return const MaterialApp(home: XorWebView());
//   }
// }

// class XorWebView extends StatefulWidget {
//   const XorWebView({super.key});

//   @override
//   State<XorWebView> createState() => _XorWebViewState();
// }

// class _XorWebViewState extends State<XorWebView> {
//   InAppWebViewController? webViewController;

//   @override
//   Widget build(BuildContext context) {
//     return Scaffold(
//       appBar: AppBar(title: const Text("XOR Example")),
//       body: InAppWebView(
//         initialUrlRequest: URLRequest(
//           url: WebUri("http://192.168.8.20:3000"),   // <-- external server
//         ),
//         initialSettings: InAppWebViewSettings(
//           javaScriptEnabled: true,
//           mixedContentMode: MixedContentMode.MIXED_CONTENT_ALWAYS_ALLOW,
//         ),

//         onWebViewCreated: (controller) {
//           webViewController = controller;

//           controller.addJavaScriptHandler(
//             handlerName: "xorRequest",
//             callback: (args) {
//               String plain = args[0];
//               String key = args[1];
//               String result = xorStrings(plain, key);
//               return result;
//             },
//           );
//         },
//       ),
//     );
//   }

// String xorStrings(String plain, String key) {
//   List<int> plainBytes = utf8.encode(plain);
//   List<int> keyBytes = utf8.encode(key);

//   List<int> result = [];

//   for (int i = 0; i < plainBytes.length; i++) {
//     result.add(plainBytes[i] ^ 0); // keyBytes[i % keyBytes.length]);
//   }

//   return result.map((b) => b.toRadixString(16).padLeft(2, '0')).join("");
// }

// }


import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:web_view_crypto/ll_crypto.dart';

void main() {
  runApp(const AESDemo());
}

class AESDemo extends StatelessWidget {
  const AESDemo({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AES HW Demo',
      home: AESPage(),
    );
  }
}

class AESPage extends StatefulWidget {
  @override
  State<AESPage> createState() => _AESPageState();
}

class _AESPageState extends State<AESPage> {
  final TextEditingController _inputController = TextEditingController();
  String encryptedHex = "";

  // Dummy round key schedule (15 x 16 = 240 bytes)
  // NOTE: This is NOT a real AES-256 key schedule.
  final Uint8List defaultRoundKeys =
      Uint8List.fromList(List.generate(240, (i) => i & 0xFF));

  void _encrypt() {
    final txt = _inputController.text;

    // Convert to 16-byte block (AES-128 block)
    final block = Uint8List(16);
    final bytes = Uint8List.fromList(txt.codeUnits);

    // Fill block (pad with zeros)
    for (int i = 0; i < 16 && i < bytes.length; i++) {
      block[i] = bytes[i];
    }

    try {
      final out = aesEncrypt();

      setState(() {
        encryptedHex =
            out.map((b) => b.toRadixString(16).padLeft(2, '0')).join(" ");
      });
    } catch (e) {
      setState(() => encryptedHex = "Error: $e");
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("AES-HW Demo")),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            TextField(
              controller: _inputController,
              decoration: const InputDecoration(
                labelText: "Plaintext (UTF-8, 16 bytes max)",
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _encrypt,
              child: const Text("Encrypt"),
            ),
            const SizedBox(height: 16),
            SelectableText(
              encryptedHex,
              style: const TextStyle(fontFamily: "monospace"),
            ),
          ],
        ),
      ),
    );
  }
}
