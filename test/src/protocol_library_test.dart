@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:dartssh2/protocol.dart';
import 'package:test/test.dart';

void main() {
  test('protocol library exposes codec primitives for server use', () {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSH_Message_Channel_Data.messageId);
    writer.writeUint32(4);
    // readString expects a length-prefixed string, so write it with
    // writeString (not writeBytes) for the round-trip to work.
    writer.writeString(Uint8List.fromList('data'.codeUnits));
    final payload = writer.takeBytes();

    final reader = SSHMessageReader(payload);
    // The message id is the leading uint8; the fork reads it via
    // `SSHMessage.readMessageId` or directly as the first byte here.
    expect(reader.readUint8(), SSH_Message_Channel_Data.messageId);
    expect(reader.readUint32(), 4);
    expect(reader.readString(), Uint8List.fromList('data'.codeUnits));
  });

  test('exchange-hash helper is reachable through the protocol library', () {
    // Presence check: the server transport calls this with role-swapped
    // arguments; it must be importable without src/ paths.
    expect(SSHKexUtils.computeExchangeHash, isNotNull);
  });
}
