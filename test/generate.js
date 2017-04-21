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

  it('Generation with custom byteSize', function () {
    var secret = libotp.generateSecret(50);
    assert.equal(base32.decode(secret).length, 50,
      'Should generate a secret of size 50 bytes');
  });

  it('Generation with custom encoding', function () {
    var secret = libotp.generateSecret(20, 'base64');
    assert.equal(new Buffer(secret, 'base64').length, 20,
      'Should generate a secret of size 20 bytes');
  });
});
