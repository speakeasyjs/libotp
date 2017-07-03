'use strict';

var assert = require('assert');
var base32 = require('base32.js');
var libotp = require('../libotp');

describe('Generator tests', function () {
  it('Normal generation with defaults', function () {
    var secret = libotp.generateSecret();
    assert.equal(base32.decode(secret).length, 20,
      'Should generate a secret of size 20 bytes');
  });

  it('Generation with algorithm sha256', function () {
    var secret = libotp.generateSecret('sha256');
    assert.equal(base32.decode(secret).length, 32,
      'Should generate a secret of size 32 bytes');
  });

  it('Generation with algorithm sha512', function () {
    var secret = libotp.generateSecret('sha512');
    assert.equal(base32.decode(secret).length, 64,
      'Should generate a secret of size 64 bytes');
  });

  it('Generation with custom encoding', function () {
    var secret = libotp.generateSecret('sha1', 'base64');
    assert.equal(new Buffer(secret, 'base64').length, 20,
      'Should generate a secret of size 20 bytes');
  });

  it('Generation for Buffer', function () {
    var secret = libotp.generateSecret('sha1', false);
    assert.ok(Buffer.isBuffer(secret));
    assert.equal(secret.length, 20,
      'Should generate a secret of size 20 bytes');
  });
});
