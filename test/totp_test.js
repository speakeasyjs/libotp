'use strict';

/* global describe, it */

var chai = require('chai');
var assert = chai.assert;
var TOTP = require('../libotp').TOTP;
var TOTP = require('../libotp').TOTP;

// These tests use the test vectors from RFC 6238's Appendix B: Test Vectors
// http://tools.ietf.org/html/rfc6238#appendix-B
// They use an ASCII string of 12345678901234567890 and a time step of 30s.

describe('TOTP Time-Based Algorithm Test', function () {
  describe("normal operation with secret = '12345678901234567890' at time = 59", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: '12345678901234567890', time: 59}).next();
      assert.equal(topic, '287082');
    });
  });

  describe("normal operation with secret = '12345678901234567890' at time = 59000 using key (deprecated)", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: '12345678901234567890', time: 59}).next();
      assert.equal(topic, '287082');
    });
  });

  describe("a different time normal operation with secret = '12345678901234567890' at time = 1111111109", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: '12345678901234567890', time: 1111111109}).next();
      assert.equal(topic, '081804');
    });
  });

  describe("digits parameter with secret = '12345678901234567890' at time = 1111111109000 and digits = 8", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: '12345678901234567890', time: 1111111109, digits: 8}).next();
      assert.equal(topic, '07081804');
    });
  });

  describe("hexadecimal encoding with secret = '3132333435363738393031323334353637383930' as hexadecimal at time 1111111109", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: '3132333435363738393031323334353637383930', encoding: 'hex', time: 1111111109}).next();
      assert.equal(topic, '081804');
    });
  });

  describe("base32 encoding with secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' as base32 at time 1111111109", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', encoding: 'base32', time: 1111111109}).next();
      assert.equal(topic, '081804');
    });
  });

  describe("a custom period with secret = '12345678901234567890' at time = 1111111109000 with period = 60", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: '12345678901234567890', time: 1111111109, period: 60}).next();
      assert.equal(topic, '360094');
    });
  });

  describe("initial time with secret = '12345678901234567890' at time = 1111111109000 and epoch = 1111111100", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: '12345678901234567890', time: 1111111109, epoch: 1111111100}).next();
      assert.equal(topic, '755224');
    });
  });

  describe("base32 encoding with secret = '1234567890' at time = 1111111109", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: '12345678901234567890', time: 1111111109}).next();
      assert.equal(topic, '081804');
    });
  });

  describe("base32 encoding with secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA' as base32 at time = 1111111109, digits = 8 and algorithm as 'sha256'", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA', encoding: 'base32', time: 1111111109, digits: 8, algorithm: 'sha256'}).next();
      assert.equal(topic, '68084774');
    });
  });

  describe("base32 encoding with secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA' as base32 at time = 1111111109, digits = 8 and algorithm as 'sha512'", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA', encoding: 'base32', time: 1111111109, digits: 8, algorithm: 'sha512'}).next();
      assert.equal(topic, '25091201');
    });
  });

  describe("normal operation with secret = '12345678901234567890' with overridden counter 3", function () {
    it('should return correct one-time password', function () {
      var topic = new TOTP({secret: '12345678901234567890', time: 3 * 30}).next();
      assert.equal(topic, '969429');
    });
  });

  describe('totp.diff() window tests', function () {
    var secret = 'rNONHRni6BAk7y2TiKrv';
    it('should get current TOTP value', function () {
      var topic = new TOTP({secret: secret, time: 1 * 30}).next();
      assert.equal(topic, '314097');
    });

    it('should get TOTP value at counter 3', function () {
      var topic = new TOTP({secret: secret, time: 3 * 30}).next();
      assert.equal(topic, '663640');
    });

    it('should get delta with varying window lengths', function () {
      var delta;

      delta = new TOTP({secret: secret, time: 1 * 30, window: 0}).diff('314097');
      assert.strictEqual(delta, 0);

      delta = new TOTP({secret: secret, time: 1 * 30, window: 2}).diff('314097');
      assert.strictEqual(delta, 0);

      delta = new TOTP({secret: secret, time: 1 * 30, window: 3}).diff('314097');
      assert.strictEqual(delta, 0);
    });

    it('should get delta when the item is not at specified counter but within window', function () {
      // Use token at counter 3, initial counter 1, and a window of 2
      var delta = new TOTP({secret: secret, window: 3, time: 1 * 30}).diff('663640');
      assert.strictEqual(delta, 2);
    });

    it('should not get delta when the item is not at specified counter and not within window', function () {
      // Use token at counter 3, initial counter 1, and a window of 1
      var delta = new TOTP({secret: secret, window: 1, time: 1 * 30}).diff('663640');
      assert.strictEqual(delta, false);
    });

    it('should support negative delta values when token is on the negative side of the window', function () {
      // Use token at counter 1, initial counter 3, and a window of 2
      var delta = new TOTP({secret: secret, window: 2, time: 3 * 30}).diff('314097');
      assert.strictEqual(delta, -2);
    });

    it('should support negative delta values when token is on the negative side of the window using time input', function () {
      // Use token at counter 1, initial counter 3, and a window of 2
      var delta = new TOTP({secret: secret, time: 1453854005, window: 2}).diff('625175');
      assert.strictEqual(delta, -2);
    });
  });
});
