import 'package:web/web.dart' as web;

String? sessionRead(String key) {
  try {
    return web.window.sessionStorage.getItem(key);
  } catch (_) {
    return null; // storage blocked (e.g. some privacy modes) -- behave as logged out
  }
}

void sessionWrite(String key, String value) {
  try {
    web.window.sessionStorage.setItem(key, value);
  } catch (_) {}
}

void sessionRemove(String key) {
  try {
    web.window.sessionStorage.removeItem(key);
  } catch (_) {}
}
