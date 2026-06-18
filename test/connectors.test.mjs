import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hostnameBelongsToDomain } from '../src/api/connectors.ts';

test('hostnameBelongsToDomain accepts the root domain and real subdomains', () => {
  assert.equal(hostnameBelongsToDomain('example.com', 'example.com'), true);
  assert.equal(hostnameBelongsToDomain('api.example.com', 'example.com'), true);
  assert.equal(hostnameBelongsToDomain('*.dev.example.com.', 'example.com'), true);
});

test('hostnameBelongsToDomain rejects sibling lookalike domains', () => {
  assert.equal(hostnameBelongsToDomain('badexample.com', 'example.com'), false);
  assert.equal(hostnameBelongsToDomain('example.com.attacker.net', 'example.com'), false);
  assert.equal(hostnameBelongsToDomain('not-example.com', 'example.com'), false);
});
