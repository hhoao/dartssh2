// Uses dart:mirrors, which is VM-only.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/message/msg_kex.dart';
import 'package:dartssh2/src/message/msg_service.dart';
import 'package:dartssh2/src/message/msg_unimplemented.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:test/test.dart';

void main() {
  final transportLibrary = reflectClass(SSHTransport).owner as LibraryMirror;

  Symbol privateSymbol(String name) =>
      MirrorSystem.getSymbol(name, transportLibrary);

  void setPrivate(SSHTransport transport, String field, Object? value) {
    reflect(transport).setField(privateSymbol(field), value);
  }

  T getPrivate<T>(SSHTransport transport, String field) {
    return reflect(transport).getField(privateSymbol(field)).reflectee as T;
  }

  Future<void> invokePrivate(
    SSHTransport transport,
    String method,
    List<Object?> args,
  ) async {
    final result = reflect(transport).invoke(privateSymbol(method), args);
    final value = result.reflectee;
    if (value is Future) await value;
  }

  SSH_Message_KexInit serverKexInit() {
    return SSH_Message_KexInit(
      kexAlgorithms: [SSHKexType.x25519.name],
      serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
      encryptionClientToServer: [SSHCipherType.aes128ctr.name],
      encryptionServerToClient: [SSHCipherType.aes128ctr.name],
      macClientToServer: [SSHMacType.hmacSha256.name],
      macServerToClient: [SSHMacType.hmacSha256.name],
      compressionClientToServer: const ['none'],
      compressionServerToClient: const ['none'],
      firstKexPacketFollows: false,
    );
  }

  /// Prepares the state [_applyRemoteKeys] needs so a NEWKEYS can be handled.
  void prepareKeys(SSHTransport transport) {
    setPrivate(transport, '_kexType', SSHKexType.x25519);
    setPrivate(transport, '_sharedSecret', BigInt.from(42));
    setPrivate(transport, '_exchangeHash',
        Uint8List.fromList(List<int>.filled(32, 1)));
    setPrivate(
        transport, '_sessionId', Uint8List.fromList(List<int>.filled(32, 2)));
    setPrivate(transport, '_clientCipherType', SSHCipherType.aes128ctr);
    setPrivate(transport, '_serverCipherType', SSHCipherType.aes128ctr);
    setPrivate(transport, '_clientMacType', SSHMacType.hmacSha256);
    setPrivate(transport, '_serverMacType', SSHMacType.hmacSha256);
  }

  /// Simulates the state of a transport mid-rekey: the initial exchange is
  /// long done, our KEXINIT and NEWKEYS are out, and the peer's KEXINIT has
  /// arrived — only its NEWKEYS is still outstanding.
  void midRekey(SSHTransport transport) {
    setPrivate(transport, '_isFirstKex', false);
    setPrivate(transport, '_kexInProgress', true);
    setPrivate(transport, '_sentKexInit', true);
    setPrivate(transport, '_receivedKexInit', true);
    setPrivate(transport, '_sentNewKeys', true);
    setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
  }

  /// Whether the transport wrote an SSH_MSG_UNIMPLEMENTED to [socket].
  bool sentUnimplemented(_CaptureSSHSocket socket) {
    for (final packet in socket.packets.skip(1)) {
      final paddingLength = SSHPacket.readPaddingLength(packet);
      final payload = Uint8List.sublistView(
        packet,
        SSHPacket.headerLength,
        packet.length - paddingLength,
      );
      if (SSHMessage.readMessageId(payload) ==
          SSH_Message_Unimplemented.messageId) {
        return true;
      }
    }
    return false;
  }

  group('F6: messages racing the rekey window are queued, not dropped', () {
    test('a channel message mid-rekey is delivered after NEWKEYS', () async {
      final socket = _CaptureSSHSocket();
      final received = <int>[];
      final transport = SSHTransport(
        socket,
        onMessage: (payload) {
          received.add(SSHMessage.readMessageId(payload));
          return true;
        },
      );

      midRekey(transport);
      prepareKeys(transport);

      final channelData = SSH_Message_Channel_Data(
        recipientChannel: 0,
        data: Uint8List.fromList([1, 2, 3]),
      ).encode();
      await invokePrivate(transport, '_handleMessage', [channelData]);

      // Not dropped, not answered UNIMPLEMENTED: it waits for the exchange.
      expect(received, isEmpty);
      expect(sentUnimplemented(socket), isFalse);

      await invokePrivate(transport, '_handleMessageNewKeys', [
        SSH_Message_NewKeys().encode(),
      ]);

      expect(received, [SSH_Message_Channel_Data.messageId]);

      transport.close();
    });

    test('a channel teardown mid-rekey is delivered after NEWKEYS', () async {
      // B02's exact casualty: the exit-status/EOF/CLOSE trailing the rekey
      // KEXINIT used to be dropped, hanging the channel forever.
      final socket = _CaptureSSHSocket();
      final received = <int>[];
      final transport = SSHTransport(
        socket,
        onMessage: (payload) {
          received.add(SSHMessage.readMessageId(payload));
          return true;
        },
      );

      midRekey(transport);
      prepareKeys(transport);

      await invokePrivate(transport, '_handleMessage', [
        SSH_Message_Channel_Close(recipientChannel: 0).encode(),
      ]);
      expect(received, isEmpty);

      await invokePrivate(transport, '_handleMessageNewKeys', [
        SSH_Message_NewKeys().encode(),
      ]);

      expect(received, [SSH_Message_Channel_Close.messageId]);

      transport.close();
    });

    test('queued messages are replayed in arrival order', () async {
      final socket = _CaptureSSHSocket();
      final received = <int>[];
      final transport = SSHTransport(
        socket,
        onMessage: (payload) {
          received.add(SSHMessage.readMessageId(payload));
          return true;
        },
      );

      midRekey(transport);
      prepareKeys(transport);

      await invokePrivate(transport, '_handleMessage', [
        SSH_Message_Channel_Data(
          recipientChannel: 0,
          data: Uint8List.fromList([1]),
        ).encode(),
      ]);
      await invokePrivate(transport, '_handleMessage', [
        SSH_Message_Channel_EOF(recipientChannel: 0).encode(),
      ]);
      await invokePrivate(transport, '_handleMessage', [
        SSH_Message_Channel_Close(recipientChannel: 0).encode(),
      ]);

      await invokePrivate(transport, '_handleMessageNewKeys', [
        SSH_Message_NewKeys().encode(),
      ]);

      expect(received, [
        SSH_Message_Channel_Data.messageId,
        SSH_Message_Channel_EOF.messageId,
        SSH_Message_Channel_Close.messageId,
      ]);

      transport.close();
    });

    test('transport-range messages (< 50) still draw UNIMPLEMENTED mid-rekey',
        () async {
      // kex_reset_dispatch only guards 1-49 (kex.c): SERVICE_REQUEST is
      // answered UNIMPLEMENTED through a rekey, never queued.
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      midRekey(transport);

      await invokePrivate(transport, '_handleMessage', [
        SSH_Message_Service_Request('ssh-userauth').encode(),
      ]);

      expect(sentUnimplemented(socket), isTrue);

      transport.close();
    });

    test('the queue is one exchange deep: messages after NEWKEYS flow again',
        () async {
      final socket = _CaptureSSHSocket();
      final received = <int>[];
      final transport = SSHTransport(
        socket,
        onMessage: (payload) {
          received.add(SSHMessage.readMessageId(payload));
          return true;
        },
      );

      midRekey(transport);
      prepareKeys(transport);

      await invokePrivate(transport, '_handleMessageNewKeys', [
        SSH_Message_NewKeys().encode(),
      ]);
      await invokePrivate(transport, '_handleMessage', [
        SSH_Message_Channel_Data(
          recipientChannel: 0,
          data: Uint8List.fromList([1]),
        ).encode(),
      ]);

      expect(received, [SSH_Message_Channel_Data.messageId]);

      transport.close();
    });

    test('a strict-kex violation during the initial exchange stays fatal',
        () async {
      // The initial exchange never queues: OpenSSH answers everything
      // through dispatch_protocol_error there (fatal under strict kex).
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_strictKex', true);
      setPrivate(transport, '_isFirstKex', true);
      setPrivate(transport, '_kexInProgress', true);

      await expectLater(
        invokePrivate(transport, '_handleMessage', [
          SSH_Message_Channel_Data(
            recipientChannel: 0,
            data: Uint8List.fromList([1]),
          ).encode(),
        ]),
        throwsA(isA<SSHHandshakeError>()),
      );

      transport.close();
    });

    test('a channel message during a non-strict initial exchange draws UNIMPLEMENTED',
        () async {
      final socket = _CaptureSSHSocket();
      final received = <int>[];
      final transport = SSHTransport(
        socket,
        onMessage: (payload) {
          received.add(SSHMessage.readMessageId(payload));
          return true;
        },
      );

      setPrivate(transport, '_strictKex', false);
      setPrivate(transport, '_isFirstKex', true);
      setPrivate(transport, '_kexInProgress', true);

      await invokePrivate(transport, '_handleMessage', [
        SSH_Message_Channel_Data(
          recipientChannel: 0,
          data: Uint8List.fromList([1]),
        ).encode(),
      ]);

      expect(received, isEmpty);
      expect(sentUnimplemented(socket), isTrue);

      transport.close();
    });
  });

  group('F10: a duplicate KEXINIT mid-exchange is rejected, not merged', () {
    test('the second KEXINIT draws UNIMPLEMENTED and leaves the exchange alone',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      midRekey(transport);
      final sentinel = Uint8List.fromList([9, 9, 9]);
      setPrivate(transport, '_remoteKexInit', sentinel);

      await invokePrivate(transport, '_handleMessageKexInit', [
        serverKexInit().encode(),
      ]);

      // sshd re-registers KEXINIT to kex_protocol_error for the duration of
      // the exchange (kex.c:kex_input_kexinit): the duplicate is answered
      // UNIMPLEMENTED, the in-flight negotiation is untouched.
      expect(sentUnimplemented(socket), isTrue);
      expect(getPrivate<Uint8List>(transport, '_remoteKexInit'), same(sentinel));
      expect(getPrivate<bool>(transport, '_kexInProgress'), isTrue);
      expect(transport.isClosed, isFalse);

      transport.close();
    });

    test('the first KEXINIT of a round is still processed', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      // We initiated the rekey (our KEXINIT is out), the peer's answer is
      // the first one this round: it must be negotiated as usual.
      midRekey(transport);
      setPrivate(transport, '_receivedKexInit', false);

      final payload = serverKexInit().encode();
      await invokePrivate(transport, '_handleMessageKexInit', [payload]);

      expect(sentUnimplemented(socket), isFalse);
      expect(getPrivate<Uint8List>(transport, '_remoteKexInit'), payload);

      transport.close();
    });

    test('a duplicate KEXINIT during the initial strict exchange is fatal',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_strictKex', true);
      setPrivate(transport, '_isFirstKex', true);
      setPrivate(transport, '_kexInProgress', true);
      setPrivate(transport, '_sentKexInit', true);
      setPrivate(transport, '_receivedKexInit', true);

      await expectLater(
        invokePrivate(transport, '_handleMessageKexInit', [
          serverKexInit().encode(),
        ]),
        throwsA(isA<SSHHandshakeError>()),
      );

      transport.close();
    });
  });

  group('F11: an unsolicited NEWKEYS is not adopted', () {
    test('a NEWKEYS with no exchange in progress draws UNIMPLEMENTED',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_isFirstKex', false);
      setPrivate(transport, '_kexInProgress', false);

      await invokePrivate(transport, '_handleMessageNewKeys', [
        SSH_Message_NewKeys().encode(),
      ]);

      expect(sentUnimplemented(socket), isTrue);
      expect(transport.isClosed, isFalse);

      transport.close();
    });

    test('a NEWKEYS racing the exchange before our own draws UNIMPLEMENTED',
        () async {
      // B08's shape: the rogue NEWKEYS lands between the peer's KEXINIT and
      // our KEXDH_REPLY processing. The exchange must survive it.
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      midRekey(transport);
      setPrivate(transport, '_receivedKexInit', false);
      setPrivate(transport, '_sentNewKeys', false);

      await invokePrivate(transport, '_handleMessageNewKeys', [
        SSH_Message_NewKeys().encode(),
      ]);

      expect(sentUnimplemented(socket), isTrue);
      expect(getPrivate<bool>(transport, '_kexInProgress'), isTrue);
      expect(getPrivate<bool>(transport, '_sentNewKeys'), isFalse);
      expect(transport.isClosed, isFalse);

      transport.close();
    });

    test('a NEWKEYS after we sent ours is still applied', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      midRekey(transport);
      setPrivate(transport, '_receivedKexInit', false);
      setPrivate(transport, '_sentNewKeys', true);
      prepareKeys(transport);

      await invokePrivate(transport, '_handleMessageNewKeys', [
        SSH_Message_NewKeys().encode(),
      ]);

      expect(sentUnimplemented(socket), isFalse);
      expect(getPrivate<bool>(transport, '_kexInProgress'), isFalse);
      expect(getPrivate<bool>(transport, '_sentNewKeys'), isFalse);

      transport.close();
    });
  });

  group('F12: server-side pre-banner garbage is fatal', () {
    test('a garbage line before the client version closes the connection',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, isServer: true);

      socket.addIncoming('xxxx\r\n');

      await expectLater(
        transport.done,
        throwsA(isA<SSHHandshakeError>()),
      );

      // The server banner went out first, then the plaintext error line.
      expect(latin1.decode(socket.packets[0]), startsWith('SSH-2.0-'));
      expect(
        socket.packets.skip(1).map(latin1.decode),
        contains('Invalid SSH identification string.\r\n'),
      );
    });

    test('a garbage line is fatal even when a valid version follows it',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, isServer: true);

      socket.addIncoming('xxxx\r\nSSH-2.0-OpenSSH_9.6\r\n');

      await expectLater(
        transport.done,
        throwsA(isA<SSHHandshakeError>()),
      );
      expect(transport.remoteVersion, isNull);
    });

    test('the server completes a clean version exchange', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, isServer: true);

      socket.addIncoming('SSH-2.0-OpenSSH_9.6\r\n');
      await _pumpUntil(() => transport.remoteVersion != null);

      expect(transport.remoteVersion, 'SSH-2.0-OpenSSH_9.6');

      transport.close();
    });

    test('the client still tolerates server pre-banner comment lines',
        () async {
      // RFC 4253 §4.2: the client must accept server comments; only the
      // server-side tolerance was the defect.
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      socket.addIncoming('Welcome to our SSH server!\r\n');
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(transport.remoteVersion, isNull);

      socket.addIncoming('SSH-2.0-OpenSSH_9.6\r\n');
      await _pumpUntil(() => transport.remoteVersion != null);

      expect(transport.remoteVersion, 'SSH-2.0-OpenSSH_9.6');

      transport.close();
    });
  });
}

Future<void> _pumpUntil(bool Function() condition) async {
  for (var i = 0; i < 50; i++) {
    if (condition()) {
      return;
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  fail('Timed out waiting for condition');
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

  void addIncoming(String data) {
    _inputController.add(Uint8List.fromList(latin1.encode(data)));
  }

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
