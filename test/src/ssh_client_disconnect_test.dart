import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_disconnect.dart';
import 'package:test/test.dart';

void main() {
  group('SSHClient.disconnect', () {
    test('sends SSH_MSG_DISCONNECT before closing', () async {
      final socket = _CaptureSSHSocket();
      final client = SSHClient(socket, username: 'test');

      await client.disconnect();

      expect(client.isClosed, isTrue);
      final message = _findDisconnectMessage(socket.packets);
      expect(message, isNotNull,
          reason: 'a disconnect packet must reach the wire before the close');
      expect(message!.reasonCode, SSHDisconnectReason.byApplication.code);
      expect(
          message.description, SSHDisconnectReason.byApplication.description);
    });

    test('is a no-op on an already closed client', () async {
      final socket = _CaptureSSHSocket();
      final client = SSHClient(socket, username: 'test');
      await client.close();

      await client.disconnect();

      expect(client.isClosed, isTrue);
    });
  });
}

/// Scans raw socket writes for an unencrypted `SSH_MSG_DISCONNECT` packet.
///
/// Before the first key exchange packets are sent in the clear, so the wire
/// format is directly parseable: 4-byte length, 1-byte padding length, then
/// the payload. Writes that are not binary packets (the version line) are
/// skipped by the length sanity check.
SSH_Message_Disconnect? _findDisconnectMessage(List<Uint8List> writes) {
  for (final write in writes) {
    if (write.length < 6) continue;
    final payloadLength =
        write[0] << 24 | write[1] << 16 | write[2] << 8 | write[3];
    if (payloadLength < 1 || payloadLength + 4 > write.length) continue;
    final payload = write.sublist(5, 4 + payloadLength);
    if (payload.isEmpty || payload[0] != SSH_Message_Disconnect.messageId) {
      continue;
    }
    return SSH_Message_Disconnect.decode(
      Uint8List.fromList(
          [SSH_Message_Disconnect.messageId, ...payload.sublist(1)]),
    );
  }
  return null;
}

class _CaptureSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final packets = <Uint8List>[];

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _CaptureSink(packets);

  @override
  Future<void> get done => _doneCompleter.future;

  @override
  Future<void> close() async {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    await _inputController.close();
  }

  @override
  void destroy() {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    unawaited(_inputController.close());
  }

  @override
  Future<void> flush() async {}
}

class _CaptureSink implements StreamSink<List<int>> {
  _CaptureSink(this._packets);

  final List<Uint8List> _packets;

  @override
  void add(List<int> data) {
    _packets.add(Uint8List.fromList(data));
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
