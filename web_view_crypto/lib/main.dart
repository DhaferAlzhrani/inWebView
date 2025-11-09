// lib/main.dart
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

typedef JsonMap = Map<String, dynamic>;
typedef HandlerFn = FutureOr<JsResult> Function(JsonMap data);

enum ErrorCode { VALIDATION_FAILED, TIMEOUT, INTERNAL }

class JsResult {
  final bool ok;
  final JsonMap data;
  final ErrorCode? code;
  final String? message;

  JsResult.success([JsonMap? data])
    : ok = true,
      data = data ?? const {},
      code = null,
      message = null;

  JsResult.error(this.code, {this.message, JsonMap? data})
    : ok = false,
      data = data ?? const {};

  JsonMap toJson() => {
    'ok': ok,
    'data': data,
    if (!ok && code != null) 'code': code.toString().split('.').last,
    if (!ok && message != null) 'message': message,
  };
}

class HandlerRegistration {
  final HandlerFn fn;
  final List<String> required;
  final Map<String, Type> types;
  final int timeoutMs;
  final bool isNoArgAllowed;

  HandlerRegistration({
    required this.fn,
    this.required = const [],
    this.types = const {},
    this.timeoutMs = 15000,
    this.isNoArgAllowed = false,
  });
}

class JsBridge {
  final InAppWebViewController controller;
  JsBridge(this.controller);

  void register(Map<String, HandlerRegistration> handlers) {
    handlers.forEach((name, spec) {
      controller.addJavaScriptHandler(
        handlerName: name,
        callback: (args) async {
          if (kDebugMode) debugPrint("[$name] raw args: $args");
          JsonMap data = {};

          if (!spec.isNoArgAllowed) {
            data = _validateArg(args);
            if (data.isEmpty) {
              return JsResult.error(
                ErrorCode.VALIDATION_FAILED,
                message: "Expected single JSON object argument.",
              ).toJson();
            }
            final err = _validateSchema(
              data,
              requiredKeys: spec.required,
              types: spec.types,
            );
            if (err != null) return err.toJson();
          }

          try {
            final future = Future.value(spec.fn(data));
            final out = await future.timeout(
              Duration(milliseconds: spec.timeoutMs),
              onTimeout: () {
                return JsResult.error(
                  ErrorCode.TIMEOUT,
                  message: "Timeout: operation took too long!",
                );
              },
            );
            return out.toJson();
          } on TimeoutException {
            return JsResult.error(ErrorCode.TIMEOUT).toJson();
          } catch (e, st) {
            if (kDebugMode) {
              debugPrint("[$name] error: $e");
              debugPrint("$st");
            }
            return JsResult.error(
              ErrorCode.INTERNAL,
              message: "Internal error",
            ).toJson();
          }
        },
      );
    });
  }

  JsonMap _validateArg(List<dynamic> args) {
    if (args.isEmpty) return {};
    final first = args.first;
    if (first is Map) {
      return first.map((k, v) => MapEntry(k.toString(), v));
    }
    return {};
  }

  JsResult? _validateSchema(
    JsonMap data, {
    List<String> requiredKeys = const [],
    Map<String, Type> types = const {},
  }) {
    for (final key in requiredKeys) {
      if (!data.containsKey(key)) {
        return JsResult.error(
          ErrorCode.VALIDATION_FAILED,
          message: "Missing required key: $key",
        );
      }
    }
    for (final e in types.entries) {
      final k = e.key;
      final t = e.value;
      if (!data.containsKey(k)) continue;
      final v = data[k];
      if (v != null && v.runtimeType != t) {
        return JsResult.error(
          ErrorCode.VALIDATION_FAILED,
          message: "Invalid type for '$k'. Expected $t, got ${v.runtimeType}",
        );
      }
    }
    return null;
  }
}

// ===== XOR handler (supports UTF-8 or HEX input, returns HEX or UTF-8) =====
FutureOr<JsResult> xorHandler(JsonMap data) {
  final keyStr = (data['key'] as String?) ?? '';
  final plainStr = (data['plain'] as String?) ?? '';
  final encoding = (data['encoding'] as String?) ?? 'utf8'; // 'utf8' | 'hex'
  final output = (data['output'] as String?) ?? 'hex'; // 'hex' | 'utf8'

  Uint8List keyBytes, plainBytes;

  if (encoding == 'hex') {
    keyBytes = _fromHex(keyStr);
    plainBytes = _fromHex(plainStr);
  } else {
    keyBytes = Uint8List.fromList(utf8.encode(keyStr));
    plainBytes = Uint8List.fromList(utf8.encode(plainStr));
  }

  final out = Uint8List(plainBytes.length);
  for (var i = 0; i < plainBytes.length; i++) {
    final k = keyBytes.isEmpty ? 0 : keyBytes[i % keyBytes.length];
    out[i] = plainBytes[i] ^ k;
  }

  final hex = _toHex(out);
  final text = utf8.decode(out, allowMalformed: true);

  if (output == 'utf8') {
    return JsResult.success({'len': out.length, 'text': text});
  }
  return JsResult.success({'len': out.length, 'hex': hex});
}

Uint8List _fromHex(String hex) {
  final h = hex.trim().toLowerCase().replaceAll(RegExp(r'[^0-9a-f]'), '');
  if (h.isEmpty) return Uint8List(0);
  final even = h.length.isOdd ? '0$h' : h;
  final out = Uint8List(even.length ~/ 2);
  for (int i = 0; i < out.length; i++) {
    out[i] = int.parse(even.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

// ====================== App ======================

WebViewEnvironment? webViewEnvironment;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  if (!kIsWeb && defaultTargetPlatform == TargetPlatform.windows) {
    final available = await WebViewEnvironment.getAvailableVersion();
    assert(
      available != null,
      'WebView2 Runtime or Edge (non-stable) not found.',
    );
    webViewEnvironment = await WebViewEnvironment.create(
      settings: WebViewEnvironmentSettings(userDataFolder: 'YOUR_CUSTOM_PATH'),
    );
  }

  if (!kIsWeb && defaultTargetPlatform == TargetPlatform.android) {
    await InAppWebViewController.setWebContentsDebuggingEnabled(kDebugMode);
    // (اختياري) لو غيرت اسم الجسر الافتراضي:
    // await InAppWebViewController.setJavaScriptBridgeName('flutter_inappwebview');
  }

  runApp(const MaterialApp(home: MyApp()));
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});
  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final browser = MyInAppBrowser(webViewEnvironment: webViewEnvironment);

  final settings = InAppBrowserClassSettings(
    browserSettings: InAppBrowserSettings(hideUrlBar: false),
    webViewSettings: InAppWebViewSettings(
      javaScriptEnabled: true,
      useOnLoadResource: true,
      safeBrowsingEnabled: false,
      supportZoom: false,
      builtInZoomControls: false,
      displayZoomControls: false,
      databaseEnabled: true,
      domStorageEnabled: true,
      iframeAllowFullscreen: true,
      iframeAllow: "camera; microphone",
      useShouldOverrideUrlLoading: true,
      allowBackgroundAudioPlaying: true, //allow camera to work in background
      geolocationEnabled: false,
      mediaPlaybackRequiresUserGesture:
          false, //put it as false to enable the sound.
      networkAvailable: true,
      // userAgent: 'MakeenApp/${AppConfig.currentPlatform}',
      disableDefaultErrorPage: true,
      disableContextMenu:
          true, //disable js menu usually offers options like "Copy," "Select," "Paste," or "Inspect Element
      rendererPriorityPolicy: RendererPriorityPolicy(
        waivedWhenNotVisible: false,
        rendererRequestedPriority: RendererPriority.RENDERER_PRIORITY_IMPORTANT,
      ), //system will treat the renderer as important and less likely to be killed.
      userAgent:
          "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 Safari/537.36",
    ),
  );

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('InAppBrowser + JS Bridge')),
      body: Center(
        child: ElevatedButton(
          child: const Text('Open InAppBrowser'),
          onPressed: () {
            final url = WebUri("http://192.168.8.20:3000/?v=7"); // cache-buster
            browser.openUrlRequest(
              urlRequest: URLRequest(url: url),
              settings: settings,
            );
          },
        ),
      ),
    );
  }
}

class MyInAppBrowser extends InAppBrowser {
  MyInAppBrowser({super.webViewEnvironment});

  @override
  Future onBrowserCreated() async {
    debugPrint("Browser Created");
  }

  @override
  Future onLoadStart(url) async {
    debugPrint("Started $url");
  }

  @override
  Future onLoadStop(url) async {
    debugPrint("Stopped $url");
    final c = webViewController;
    if (c == null) return;

    // Register handlers via JsBridge
    final bridge = JsBridge(c);
    bridge.register({
      // Single object argument: { key, plain, encoding?, output? }
      'xor': HandlerRegistration(
        fn: xorHandler,
        required: ['key', 'plain'],
        types: {
          'key': String,
          'plain': String,
          'encoding': String,
          'output': String,
        },
        timeoutMs: 15000,
      ),
    });

    // Announce to the page that the platform (and handlers) are ready
    await c.evaluateJavascript(
      source: """
      window.dispatchEvent(new Event("flutterInAppWebViewPlatformReady"));
      console.log("flutterInAppWebViewPlatformReady fired");
    """,
    );
  }

  // URL-scheme fallback: bridge://xor?key=...&plain=...
  @override
  Future<NavigationActionPolicy?> shouldOverrideUrlLoading(
    NavigationAction action,
  ) async {
    final uri = action.request.url;
    if (uri == null) return NavigationActionPolicy.ALLOW;
    if (uri.scheme == 'bridge' && uri.host == 'xor') {
      final key = uri.queryParameters['key'] ?? '';
      final plain = uri.queryParameters['plain'] ?? '';
      final result =
          xorHandler({
                'key': key,
                'plain': plain,
                'encoding': 'utf8',
                'output': 'hex',
              })
              as JsResult;
      final data = result.toJson();
      await webViewController?.evaluateJavascript(
        source: "window.onXor && window.onXor(${jsonEncode(data['data'])});",
      );
      return NavigationActionPolicy.CANCEL;
    }
    return NavigationActionPolicy.ALLOW;
  }

  @override
  void onConsoleMessage(ConsoleMessage m) {
    debugPrint("JS console [${m.messageLevel}]: ${m.message}");
  }

  @override
  void onLoadHttpError(url, statusCode, description) {
    debugPrint("HTTP $statusCode for $url: $description");
  }

  @override
  void onReceivedError(WebResourceRequest request, WebResourceError error) {
    debugPrint(
      "Load error ${request.url})",
    );
  }

  @override
  void onProgressChanged(progress) {
    debugPrint("Progress: $progress");
  }

  @override
  void onExit() {
    debugPrint("Browser closed");
  }
}
