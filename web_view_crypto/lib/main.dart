import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

import 'package:web_view_crypto/ll_crypto.dart'; // contains AesGcmFfi()

Uint8List _hexToBytes(String hex) {
  final len = hex.length;
  final out = Uint8List(len ~/ 2);
  for (int i = 0; i < len; i += 2) {
    out[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return out;
}

void main() {
  runApp(const AESDemo());
}

class AESDemo extends StatelessWidget {
  const AESDemo({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(title: "AES-GCM WebView Demo", home: AESPage());
  }
}

class AESPage extends StatefulWidget {
  @override
  State<AESPage> createState() => _AESPageState();
}

class _AESPageState extends State<AESPage> {
  InAppWebViewController? _controller;
  final _ffi = AesGcmFfi();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("AES-GCM Hardware FFI Demo")),
      body: SafeArea(
        child: InAppWebView(
          initialUrlRequest: URLRequest(
            url: WebUri("http://192.168.8.20:3000"),
          ),
          initialSettings: InAppWebViewSettings(javaScriptEnabled: true),
          onWebViewCreated: (controller) {
            _controller = controller;

            controller.addJavaScriptHandler(
              handlerName: "CryptoBridge",
              callback: _onJsMessage,
            );
          },
        ),
      ),
    );
  }

  String _hex(Uint8List b) =>
      b.map((v) => v.toRadixString(16).padLeft(2, "0")).join("");

  /// Called from JS
  Future _onJsMessage(List<dynamic> args) async {
    final tStart = DateTime.now();

    try {
      if (args.isEmpty) {
        return {"ok": false, "error": "empty"};
      }

      final obj = args[0] as Map<String, dynamic>;
      final cmd = obj["cmd"];

      if (cmd == "encrypt") {
        final key = _hexToBytes(obj["key"]);
        final iv = _hexToBytes(obj["iv"]);
        final aad = obj["aad"] != null ? _hexToBytes(obj["aad"]) : Uint8List(0);

        final plain = Uint8List.fromList(utf8.encode(obj["plain"]));

        final result = _ffi.encrypt(key: key, iv: iv, plain: plain, aad: aad);

        final tEnd = DateTime.now();
        final dt = tEnd.difference(tStart).inMicroseconds / 1000.0;

        return {
          "ok": true,
          "ciphertext": _hex(result["ciphertext"]!),
          "tag": _hex(result["tag"]!),
          "time_ms": dt.toStringAsFixed(3),
        };
      }

      // ✅ NEW: DECRYPT
      if (cmd == "decrypt") {
        final key = _hexToBytes(obj["key"]);
        final iv = _hexToBytes(obj["iv"]);
        final aad = obj["aad"] != null ? _hexToBytes(obj["aad"]) : Uint8List(0);

        final ciphertext = _hexToBytes(obj["ciphertext"]);
        final tag = _hexToBytes(obj["tag"]);

        final result = _ffi.decrypt(
          key: key,
          iv: iv,
          ciphertext: ciphertext,
          tag: tag,
          aad: aad,
        );

        final plain = utf8.decode(result);

        final tEnd = DateTime.now();
        final dt = tEnd.difference(tStart).inMicroseconds / 1000.0;

        return {"ok": true, "plain": plain, "time_ms": dt.toStringAsFixed(3)};
      }

      return {"ok": false, "error": "unknown cmd"};
    } catch (e) {
      return {"ok": false, "error": e.toString()};
    }
  }
}
