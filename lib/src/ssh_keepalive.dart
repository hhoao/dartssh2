import 'dart:async';

/// A wrapper around [Timer] that calls [ping] every [interval], and can be
/// started or stopped idempotently.
class SSHKeepAlive {
  Timer? _timer;

  final Duration interval;

  final Future Function() ping;

  /// Optional hook when [ping] fails (e.g. connection dropped). Used by the
  /// app layer for liveness/reconnect — not for silencing errors.
  final void Function(Object error, StackTrace stackTrace)? onPingFailed;

  bool _isPinging = false;

  SSHKeepAlive({
    required this.ping,
    this.interval = const Duration(seconds: 10),
    this.onPingFailed,
  });

  void start() {
    _timer ??= Timer.periodic(interval, (timer) async {
      if (_isPinging) return;
      _isPinging = true;
      try {
        await ping();
      } catch (error, stackTrace) {
        onPingFailed?.call(error, stackTrace);
      } finally {
        _isPinging = false;
      }
    });
  }

  void stop() {
    _timer?.cancel();
    _timer = null;
  }
}
