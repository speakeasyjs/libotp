'use strict';

/* global describe, it */

var chai = require('chai');
var assert = chai.assert;
var libotp = require('../libotp');
var url = require('url');

['HOTP', 'TOTP'].forEach(function (klass) {
  var OTP = libotp[klass];

  describe(klass + '#url', function () {
    it('should require secret', function () {
      assert.throws(function () {
        new OTP({
          label: 'that'
        }).url();
      }, /missing secret/);
    });

    it('should require label', function () {
      assert.throws(function () {
        new OTP({
          secret: 'hello',
          counter: 0
        }).url();
      }, /missing label/);
    });

    it('should validate algorithm', function () {
      assert.doesNotThrow(function () {
        new OTP({
          secret: 'hello',
          label: 'that',
          algorithm: 'hello',
          counter: 0
        }).url();
      }, /invalid algorithm `hello`/);
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        algorithm: 'sha1',
        counter: 0
      }).url());
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        algorithm: 'sha256',
        counter: 0
      }).url());
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        algorithm: 'sha512',
        counter: 0
      }).url());
    });

    it('should validate digits', function () {
      assert.throws(function () {
        new OTP({
          secret: 'hello',
          label: 'that',
          digits: 'hello',
          counter: 0
        }).url();
      }, /invalid digits `hello`/);
      // Non-6 and non-8 digits should not throw, but should have a warn message
      assert.doesNotThrow(function () {
        new OTP({
          secret: 'hello',
          label: 'that',
          digits: 12,
          counter: 0
        }).url();
      }, /invalid digits `12`/);
      assert.doesNotThrow(function () {
        new OTP({
          secret: 'hello',
          label: 'that',
          digits: '7',
          counter: 0
        }).url();
      }, /invalid digits `7`/);
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        digits: 6,
        counter: 0
      }).url());
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        digits: 8,
        counter: 0
      }).url());
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        digits: '6',
        counter: 0
      }).url());
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        digits: '8',
        counter: 0
      }).url());
    });

    it('should validate period', function () {
      assert.throws(function () {
        new OTP({
          secret: 'hello',
          label: 'that',
          period: 'hello',
          counter: 0
        }).url();
      }, /invalid period `hello`/);
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        period: 60,
        counter: 0
      }).url());
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        period: 121,
        counter: 0
      }).url());
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        period: '60',
        counter: 0
      }).url());
      assert.ok(new OTP({
        secret: 'hello',
        label: 'that',
        period: '121',
        counter: 0
      }).url());
    });

    it('should generate an URL compatible with the Google Authenticator app', function () {
      var otp = new OTP({
        secret: 'JBSWY3DPEHPK3PXP',
        label: 'Example:alice@google.com',
        issuer: 'Example',
        encoding: 'base32',
        counter: 0
      });
      var answer = otp.url();
      var expect = 'otpauth://' + klass.toLowerCase() +
        '/Example%3Aalice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example';
      if (klass == 'HOTP') {
        expect += '&counter=0';
      }
      assert.deepEqual(
        url.parse(answer),
        url.parse(expect)
      );
    });

    it('should generate an URL compatible with the Google Authenticator app and convert an ASCII-encoded string', function () {
      var otp = new OTP({
        secret: 'MKiNHTvmfQ',
        label: 'Example:alice@google.com',
        issuer: 'Example',
        counter: 0
      });
      var answer = otp.url();
      var expect = 'otpauth://' + klass.toLowerCase() +
        '/Example%3Aalice%40google.com?secret=JVFWSTSIKR3G2ZSR&issuer=Example';
      if (klass == 'HOTP') {
        expect += '&counter=0';
      }
      assert.deepEqual(
        url.parse(answer),
        url.parse(expect)
      );
    });
  });
});
