'use strict';

/* global describe, it */

var chai = require('chai');
var assert = chai.assert;
var HOTP = require('../libotp').HOTP;

// These tests use the information from RFC 4226's Appendix D: Test Values.
// http://tools.ietf.org/html/rfc4226#appendix-D

describe('HOTP Counter-Based Algorithm Test', function () {
  describe("normal operation with secret = '12345678901234567890' at counter 3", function () {
    it('should return correct one-time password', function () {
      var topic = new HOTP({secret: '12345678901234567890', encoding: 'ascii', counter: 3}).token();
      assert.equal(topic, '969429');
    });
  });

  describe("another counter normal operation with secret = '12345678901234567890' at counter 7", function () {
    it('should return correct one-time password', function () {
      var topic = new HOTP({secret: '12345678901234567890', encoding: 'ascii', counter: 7}).token();
      assert.equal(topic, '162583');
    });
  });

  describe("digits override with secret = '12345678901234567890' at counter 4 and digits = 8", function () {
    it('should return correct one-time password', function () {
      var topic = new HOTP({secret: '12345678901234567890', encoding: 'ascii', counter: 4, digits: 8}).token();
      assert.equal(topic, '40338314');
    });
  });

  // Backwards compatibility - deprecated
  describe("digits override with secret = '12345678901234567890' at counter 4 and digits = 8", function () {
    it('should return correct one-time password', function () {
      var topic = new HOTP({secret: '12345678901234567890', encoding: 'ascii', counter: 4, digits: 8}).token();
      assert.equal(topic, '40338314');
    });
  });

  describe("hexadecimal encoding with secret = '3132333435363738393031323334353637383930' as hexadecimal at counter 4", function () {
    it('should return correct one-time password', function () {
      var topic = new HOTP({secret: '3132333435363738393031323334353637383930', encoding: 'ascii', encoding: 'hex', counter: 4}).token();
      assert.equal(topic, '338314');
    });
  });

  describe("base32 encoding with secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' as base32 at counter 4", function () {
    it('should return correct one-time password', function () {
      var topic = new HOTP({secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', encoding: 'ascii', encoding: 'base32', counter: 4}).token();
      assert.equal(topic, '338314');
    });
  });

  describe("base32 encoding with secret = '12345678901234567890' at counter 3", function () {
    it('should return correct one-time password', function () {
      var topic = new HOTP({secret: '12345678901234567890', encoding: 'ascii', counter: 3}).token();
      assert.equal(topic, '969429');
    });
  });

  describe("base32 encoding with secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA' as base32 at counter 1, digits = 8 and algorithm as 'sha256'", function () {
    it('should return correct one-time password', function () {
      var topic = new HOTP({secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', encoding: 'ascii', encoding: 'base32', counter: 1, digits: 8, algorithm: 'sha256'}).token();
      assert.equal(topic, '46119246');
    });
  });

  describe("base32 encoding with secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA' as base32 at counter 1, digits = 8 and algorithm as 'sha512'", function () {
    it('should return correct one-time password', function () {
      var topic = new HOTP({secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', encoding: 'ascii', encoding: 'base32', counter: 1, digits: 8, algorithm: 'sha512'}).token();
      assert.equal(topic, '90693936');
    });
  });
});
