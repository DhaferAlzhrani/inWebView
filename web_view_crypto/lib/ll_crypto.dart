import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'dart:io';
import 'package:ffi/ffi.dart';

//
// ENCRYPT C-SIGNATURE
//
typedef _aes_gcm_ae_c = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>, ffi.IntPtr, // key, key_len
  ffi.Pointer<ffi.Uint8>, ffi.IntPtr, // iv, iv_len
  ffi.Pointer<ffi.Uint8>, ffi.IntPtr, // plain, plain_len
  ffi.Pointer<ffi.Uint8>, ffi.IntPtr, // aad, aad_len
  ffi.Pointer<ffi.Uint8>,             // out ciphertext
  ffi.Pointer<ffi.Uint8>,             // out tag
);

typedef _aes_gcm_ae_dart = int Function(
  ffi.Pointer<ffi.Uint8>, int,
  ffi.Pointer<ffi.Uint8>, int,
  ffi.Pointer<ffi.Uint8>, int,
  ffi.Pointer<ffi.Uint8>, int,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);

//
// DECRYPT C-SIGNATURE
//
typedef _aes_gcm_ad_c = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>, ffi.IntPtr, // key, key_len
  ffi.Pointer<ffi.Uint8>, ffi.IntPtr, // iv, iv_len
  ffi.Pointer<ffi.Uint8>, ffi.IntPtr, // crypt, crypt_len
  ffi.Pointer<ffi.Uint8>, ffi.IntPtr, // aad, aad_len
  ffi.Pointer<ffi.Uint8>,             // tag
  ffi.Pointer<ffi.Uint8>,             // out plain
);

typedef _aes_gcm_ad_dart = int Function(
  ffi.Pointer<ffi.Uint8>, int,
  ffi.Pointer<ffi.Uint8>, int,
  ffi.Pointer<ffi.Uint8>, int,
  ffi.Pointer<ffi.Uint8>, int,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
);

class AesGcmFfi {
  late final ffi.DynamicLibrary _lib;
  late final _aes_gcm_ae_dart _ae;
  late final _aes_gcm_ad_dart _ad;

  AesGcmFfi() {
    _lib = Platform.isAndroid
        ? ffi.DynamicLibrary.open("libaes_hw.so")
        : throw UnsupportedError("Only Android supported");

    _ae = _lib.lookupFunction<_aes_gcm_ae_c, _aes_gcm_ae_dart>("aes_gcm_encrypt");
    _ad = _lib.lookupFunction<_aes_gcm_ad_c, _aes_gcm_ad_dart>("aes_gcm_decrypt");
  }

  //
  // ✅ ENCRYPT
  //
  Map<String, Uint8List> encrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List plain,
    Uint8List? aad,
  }) {
    final aadBytes = aad ?? Uint8List(0);

    final pKey = _toNative(key);
    final pIV = _toNative(iv);
    final pPlain = _toNative(plain);
    final pAAD = _toNative(aadBytes);

    final pCrypt = malloc<ffi.Uint8>(plain.length);
    final pTag = malloc<ffi.Uint8>(16);

    final rc = _ae(
      pKey, key.length,
      pIV, iv.length,
      pPlain, plain.length,
      pAAD, aadBytes.length,
      pCrypt,
      pTag,
    );

    final crypt = Uint8List.fromList(pCrypt.asTypedList(plain.length));
    final tag = Uint8List.fromList(pTag.asTypedList(16));

    _free([pKey, pIV, pPlain, pAAD, pCrypt, pTag]);

    if (rc != 0) throw Exception("aes_gcm_ae failed");

    return {"ciphertext": crypt, "tag": tag};
  }

  //
  // ✅ DECRYPT
  //
  Uint8List decrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List ciphertext,
    required Uint8List tag,
    Uint8List? aad,
  }) {
    final aadBytes = aad ?? Uint8List(0);

    final pKey = _toNative(key);
    final pIV = _toNative(iv);
    final pCrypt = _toNative(ciphertext);
    final pAAD = _toNative(aadBytes);
    final pTag = _toNative(tag);

    final pPlain = malloc<ffi.Uint8>(ciphertext.length);

    final rc = _ad(
      pKey, key.length,
      pIV, iv.length,
      pCrypt, ciphertext.length,
      pAAD, aadBytes.length,
      pTag,
      pPlain,
    );

    final plain = Uint8List.fromList(pPlain.asTypedList(ciphertext.length));

    _free([pKey, pIV, pCrypt, pAAD, pTag, pPlain]);

    if (rc != 0) throw Exception("aes_gcm_ad verify failed");

    return plain;
  }

  //
  // Helpers
  //
  ffi.Pointer<ffi.Uint8> _toNative(Uint8List data) {
    final p = malloc<ffi.Uint8>(data.length);
    p.asTypedList(data.length).setAll(0, data);
    return p;
  }

  void _free(List<ffi.Pointer> items) {
    for (final p in items) {
      malloc.free(p);
    }
  }
}
