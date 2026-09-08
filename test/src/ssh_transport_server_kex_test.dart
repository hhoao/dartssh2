@TestOn('vm')
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/protocol.dart';
import 'package:test/test.dart';

/// Throwaway ed25519 key generated for this test file only
/// (ssh-keygen -t ed25519 -N '' -C 'tp-sshd-task2-throwaway').
const _throwawayHostKeyPem = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAOAJT8z9/s6VSrLTOfJ3z+kzOwsciUsz3aHiluqrUF/QAAAKAqcuqHKnLq
hwAAAAtzc2gtZWQyNTUxOQAAACAOAJT8z9/s6VSrLTOfJ3z+kzOwsciUsz3aHiluqrUF/Q
AAAEBvXWGn7PPdqPHgcGghQECWfnsyXib3HYGmmZOjHbIsqQ4AlPzP3+zpVKstM58nfP6T
M7CxyJSzPdoeKW6qtQX9AAAAF3RwLXNzaGQtdGFzazItdGhyb3dhd2F5AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
''';

/// Minimal paired in-memory [SSHSocket]. Each end's sink writes are delivered
/// to the other end's stream, and closing or destroying either end shuts the
/// whole pair down.
class _LoopbackSSHSocket implements SSHSocket {
  _LoopbackSSHSocket._();

  /// Creates a connected pair of sockets.
  static (_LoopbackSSHSocket, _LoopbackSSHSocket) pair() {
    final a = _LoopbackSSHSocket._();
    final b = _LoopbackSSHSocket._();
    a._peer = b;
    b._peer = a;
    return (a, b);
  }

  late final _LoopbackSSHSocket _peer;
  final _controller = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  var _isShutdown = false;

  @override
  Stream<Uint8List> get stream => _controller.stream;

  @override
  StreamSink<List<int>> get sink => _peer._controller.sink;

  @override
  Future<void> get done => _doneCompleter.future;

  @override
  Future<void> close() async {
    _shutdown();
    _peer._shutdown();
  }

  @override
  void destroy() {
    _shutdown();
    _peer._shutdown();
  }

  void _shutdown() {
    if (_isShutdown) return;
    _isShutdown = true;
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    unawaited(_controller.close());
  }

  @override
  Future<void> flush() async {}
}

void main() {
  test('server transport completes ECDH kex and reaches encrypted state',
      () async {
    final hostKey = SSHKeyPair.fromPem(_throwawayHostKeyPem).single;

    final (clientSocket, serverSocket) = _LoopbackSSHSocket.pair();
    var hostKeySeen = false;

    // Service requests are ordinary post-KEX messages that reach onMessage;
    // sending one in each direction proves the encrypted channel is up both
    // ways. (SSH_MSG_IGNORE would not work here: the transport consumes it
    // internally and never forwards it to onMessage.)
    final clientEchoed = Completer<void>();
    final serverEchoed = Completer<void>();

    late final SSHTransport client;
    client = SSHTransport(
      clientSocket,
      onVerifyHostKey: (type, fingerprint) {
        hostKeySeen = true;
        return true;
      },
      onReady: () => client.sendPacket(
        SSH_Message_Service_Request('client-up').encode(),
      ),
      onMessage: (payload) {
        if (!clientEchoed.isCompleted &&
            SSHMessage.readMessageId(payload) ==
                SSH_Message_Service_Request.messageId) {
          clientEchoed.complete();
        }
        return true;
      },
    );
    late final SSHTransport server;
    server = SSHTransport(
      serverSocket,
      isServer: true,
      hostKeyPair: hostKey,
      onReady: () => server.sendPacket(
        SSH_Message_Service_Request('server-up').encode(),
      ),
      onMessage: (payload) {
        if (!serverEchoed.isCompleted &&
            SSHMessage.readMessageId(payload) ==
                SSH_Message_Service_Request.messageId) {
          serverEchoed.complete();
        }
        return true;
      },
    );

    await serverEchoed.future.timeout(const Duration(seconds: 5));
    await clientEchoed.future.timeout(const Duration(seconds: 5));
    expect(hostKeySeen, isTrue,
        reason: 'client must verify the server host key signature');
    expect(client.isClosed, isFalse);
    expect(server.isClosed, isFalse);

    await client.close();
    await server.close();
  });

  test('server transport refuses kex without a host key', () async {
    final (clientSocket, serverSocket) = _LoopbackSSHSocket.pair();
    final server = SSHTransport(serverSocket, isServer: true);
    final client = SSHTransport(clientSocket); // drive the handshake

    await expectLater(
      server.done,
      throwsA(isA<SSHStateError>()),
    );
    await client.done.timeout(const Duration(seconds: 5));
  });
}
