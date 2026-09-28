import assert from 'node:assert/strict';
import {mkdtempSync, symlinkSync, writeFileSync, chmodSync, mkdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
import {JsonlDecoder, loadOverlay, sameWindowIdentity, validateDriverPath, windowIdentity} from './cua-readonly-proxy-core.mjs';

test('missing overlay fails closed', () => assert.equal(loadOverlay(join(tmpdir(), 'openduck-overlay-does-not-exist')), null));

test('driver path requires absolute regular non-writable non-symlink file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'openduck-cua-'));
  const file = join(dir, 'driver'); writeFileSync(file, '#!/bin/sh\n'); chmodSync(file, 0o700);
  assert.equal(validateDriverPath('relative-driver'), '');
  assert.equal(validateDriverPath(file), '');
  const link = join(dir, 'link'); symlinkSync(file, link);
  assert.equal(validateDriverPath(link), '');
  chmodSync(file, 0o702); assert.equal(validateDriverPath(file), '');
});

test('driver path rejects traversal and writable nested ancestry', () => {
  const root = mkdtempSync(join(tmpdir(), 'openduck-root-'));
  const nested = join(root, 'nested');
  const file = join(nested, 'driver');
  mkdirSync(nested); writeFileSync(file, '#!/bin/sh\n'); chmodSync(file, 0o700);
  assert.equal(validateDriverPath(join(root, '..', 'driver'), root), '');
  assert.equal(validateDriverPath(file, root), '');
  chmodSync(nested, 0o777); assert.equal(validateDriverPath(file, root), '');
});

test('decoder handles chunk-split JSONL and id zero', () => {
  const d = new JsonlDecoder(1024);
  assert.deepEqual(d.push('{"id":'), []);
  assert.deepEqual(d.push('0,"result":true}\n'), [{id: 0, result: true}]);
});

test('decoder preserves split UTF-8 code points', () => {
  const d = new JsonlDecoder(1024);
  const encoded = Buffer.from('{"text":"✓"}\n');
  assert.deepEqual(d.push(encoded.subarray(0, encoded.length - 3)), []);
  assert.deepEqual(d.push(encoded.subarray(encoded.length - 3)), [{text: '✓'}]);
});

test('decoder rejects oversized frames', () => {
  const d = new JsonlDecoder(8);
  assert.throws(() => d.push('123456789\n'), /frame exceeded/);
  const b = new JsonlDecoder(8);
  assert.throws(() => b.push('123456789012345678'), /frame buffer exceeded/);
});

test('window identity detects bundle replacement', () => {
  const before = windowIdentity({pid: 7, window_id: 2, bundle_id: 'allowed.app'});
  assert.equal(sameWindowIdentity(before, windowIdentity({pid: 7, window_id: 2, bundle_id: 'allowed.app'})), true);
  assert.equal(sameWindowIdentity(before, windowIdentity({pid: 7, window_id: 2, bundle_id: 'other.app'})), false);
});
