/// Tab-scoped persistence for the login session. On the web this is the
/// browser's sessionStorage: it survives a reload or the browser's Back /
/// Forward buttons leaving and re-entering the app, but is cleared when
/// the tab is closed -- a deliberate middle ground between the old
/// in-memory-only token (any reload logged you out) and localStorage
/// (which would keep a bearer token around indefinitely). On any other
/// platform it's a no-op, so the session stays in memory as before.
export 'session_store_stub.dart'
    if (dart.library.js_interop) 'session_store_web.dart';
