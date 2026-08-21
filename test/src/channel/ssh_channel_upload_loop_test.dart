import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:test/test.dart';

void main() {
  test('upload loop swallows send after transport is closed', () async {
    final errors = <Object>[];
    await runZonedGuarded(() async {
      final controller = SSHChannelController(
        localId: 0,
        localMaximumPacketSize: 32768,
        localInitialWindowSize: 32768,
        remoteId: 0,
        remoteInitialWindowSize: 32768,
        remoteMaximumPacketSize: 32768,
        sendMessage: (_) {
          throw SSHStateError('Transport is closed');
        },
      );
      controller.channel.addData(Uint8List.fromList(const [1, 2, 3]));
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }, (error, _) => errors.add(error));

    expect(errors, isEmpty);
  });
}
