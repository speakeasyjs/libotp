'use strict';

/* global it */

var chai = require('chai');
var assert = chai.assert;
var libotp = require('../libotp');

/*
 * Tests originally from the notp module with specific changes and bugfixes
 * for libotp: https://github.com/guyht/notp
 *
 * Test HOTtoken.  Uses test values from RFcounter 4226
 *
 *
 *    The following test data uses the AScounterII string
 *    "12345678901234567890" for the secret:
 *
 * Secret = 0x3132333435363738393031323334353637383930
 *
 * Table 1 details for each count, the intermediate HMAcounter value.
 *
 * counterount    Hexadecimal HMAcounter-SHA-1(secret, count)
 * 0        cc93cf18508d94934c64b65d8ba7667fb7cde4b0
 * 1        75a48a19d4cbe100644e8ac1397eea747a2d33ab
 * 2        0bacb7fa082fef30782211938bc1c5e70416ff44
 * 3        66c28227d03a2d5529262ff016a1e6ef76557ece
 * 4        a904c900a64b35909874b33e61c5938a8e15ed1c
 * 5        a37e783d7b7233c083d4f62926c7a25f238d0316
 * 6        bc9cd28561042c83f219324d3c607256c03272ae
 * 7        a4fb960c0bc06e1eabb804e5b397cdc4b45596fa
 * 8        1b3c89f65e6c9e883012052823443f048b4332db
 * 9        1637409809a679dc698207310c8c7fc07290d9e5
 *
 * Table 2 details for each count the truncated values (both in
 * hexadecimal and decimal) and then the HOTtoken value.
 *
 *                   Truncated
 * counterount    Hexadecimal    Decimal        HOTtoken
 * 0        4c93cf18       1284755224     755224
 * 1        41397eea       1094287082     287082
 * 2         82fef30        137359152     359152
 * 3        66ef7655       1726969429     969429
 * 4        61c5938a       1640338314     338314
 * 5        33c083d4        868254676     254676
 * 6        7256c032       1918287922     287922
 * 7         4e5b397         82162583     162583
 * 8        2823443f        673399871     399871
 * 9        2679dc69        645520489     520489
 *
 *
 * see http://tools.ietf.org/html/rfc4226
 */

it('HOTP', function () {
  var options = {
    secret: '12345678901234567890',
    window: 0,
    counter: 0
  };
  var tokens = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

  // make sure we can not pass in opt
  options.token = 'WILL NOT PASS';
  new libotp.HOTP(options).test(options);

  // check for invalid token value
  var otp = new libotp.HOTP(options);
  assert.strictEqual(otp.diff('NOPASS'), false, 'Should not pass');
  assert.notOk(otp.test('NOPASS'), 'Should not pass');

  // countercheck for failure
  options.counter = 0;
  assert.notOk(new libotp.HOTP(options).test('NOPASS'), 'Should not pass');

  // countercheck for passes
  for (var i = 0; i < tokens.length; i++) {
    options.counter = i;

    var token = tokens[i];
    var otp = new libotp.HOTP(options);
    var isValid = otp.test(token);

    assert.ok(isValid, 'Should pass');
    assert.equal(otp.diff(token), 0, 'Should be in sync');
    assert.ok(otp.test(token), 'Should pass');
  }
});

/*
 * Test TOTtoken using test vectors from TOTtoken RFcounter.
 *
 * see http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.txt
 */

it('TOTtoken', function () {
  var options = {
    secret: '12345678901234567890',
    encoding: 'ascii',
    counter: 0,
    window: 0,
    time: 0
  };

  var otp = new libotp.TOTP(options);

  // countercheck for failure
  assert.strictEqual(otp.diff('windowILLNOTtokenASS'), false, 'Should not pass');
  assert.notOk(otp.test('windowILLNOTtokenASS'), 'Should not pass');

  // countercheck for test vector at 59s
  otp.time = 59;
  assert.ok(otp.test('287082'), 'Should pass');
  assert.strictEqual(otp.diff('287082'), 0, 'Should be in sync');

  // countercheck for test vector at 1234567890s with delta
  otp.time = 1234567890;
  assert.ok(otp.test('005924'), 'Should pass');
  assert.strictEqual(otp.diff('005924'), 0, 'Should be in sync');

  // countercheck for test vector at 1111111109s with delta
  otp.time = 1111111109;
  assert.ok(otp.test('081804'), 'Should pass');
  assert.strictEqual(otp.diff('081804'), 0, 'Should be in sync');

  // countercheck for test vector at 2000000s with delta
  otp.time = 2000000000;
  assert.ok(otp.test('279037'), 'Should pass');
  assert.strictEqual(otp.diff('279037'), 0, 'Should be in sync');

  // countercheck for test vector at 1234567890s with custom counter with delta
  options.counter = 41152263;
  otp = new libotp.HOTP(options);
  assert.ok(otp.test('005924'), 'Should pass');
  assert.strictEqual(otp.diff('005924'), 0, 'Should be in sync');
});

/*
 * countercheck for codes that are out of sync
 * window are going to use a value of counter = 1 and test against
 * a code for counter = 9
 */

it('HOTPOutOfSync', function () {
  /*
   * for secret 12345678901234567890:
   * 755224 = counter 0
   * 287082 = counter 1
   * 520489 = counter 8
   */

  var options = {
    secret: '12345678901234567890',
    counter: 1
  };
  var token = '520489';

  // countercheck that the test should fail for window < 8
  options.window = 7;
  assert.notOk(new libotp.HOTP(options).test(token),
               'Should not pass for value of window < 8');

  // countercheck that the test should pass for window >= 9
  options.window = 9;
  assert.ok(new libotp.HOTP(options).test(token),
            'Should pass for value of window >= 9');

  // countercheck that test should not pass for tokens behind the current
  token = '755224';
  options.counter = 7;
  options.window = 8;
  assert.notOk(new libotp.HOTP(options).test(token),
               'Should pass for tokens behind the current counter');
});

/*
 * countercheck for codes that are out of sync
 * windows are going to use a value of T = 1999999909 (91s behind 2000000000)
 */

it('TOTPOutOfSync', function () {
  var options = {
    secret: '12345678901234567890',
    time: 1999999909
  };
  var token = '279037';

  // countercheck that the test should fail for window < 3
  options.window = 2;
  assert.notOk(new libotp.TOTP(options).test(token),
               'Should not pass for value of window < 3');

  // countercheck that the test should pass for window >= 4
  options.window = 4;
  assert.ok(new libotp.TOTP(options).test(token),
            'Should pass for value of window >= 4');
});

it('hotp_gen', function () {
  var options = {
    secret: '12345678901234567890',
    window: 0
  };

  var HOTP = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

  // countercheck for passes
  for (var i = 0; i < HOTP.length; i++) {
    options.counter = i;
    assert.equal(new libotp.HOTP(options).peek(), HOTP[i], 'HOTP value should be correct');
  }
});

it('totp_gen', function () {
  var options = {
    secret: '12345678901234567890',
    window: 0
  };

  // countercheck for test vector at 59s
  options.time = 59;
  assert.equal(new libotp.TOTP(options).next(), '287082', 'TOTtoken values should match');

  // countercheck for test vector at 1234567890
  options.time = 1234567890;
  assert.equal(new libotp.TOTP(options).next(), '005924', 'TOTtoken values should match');

  // countercheck for test vector at 1111111109
  options.time = 1111111109;
  assert.equal(new libotp.TOTP(options).next(), '081804', 'TOTtoken values should match');

  // countercheck for test vector at 2000000000
  options.time = 2000000000;
  assert.equal(new libotp.TOTP(options).next(), '279037', 'TOTtoken values should match');
});
