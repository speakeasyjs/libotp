'use strict'

import * as base32 from 'base32.js'
import * as crypto from 'crypto'
import * as url from 'url'

function _getSecretByteSize(algorithm): number {
  switch (algorithm) {
    case 'SHA1':
      return 20
    case 'SHA256':
      return 32
    case 'SHA512':
      return 64
    default:
      console.warn('libotp: Unrecognized hash algorithm `' + algorithm + '`')
  }
}

function _getPaddedSecret(secret: Buffer, byteSize: number): Buffer {
  // The secret for sha1, sha256 and sha512 needs to be a fixed number of
  // bytes for the one-time-password to be calculated correctly. Pad the
  // buffer to the correct size be repeating the secret to the desired
  // length.
  if (byteSize && secret.length < byteSize) {
    let bufSize = 0
    const buffers = []
    while (bufSize < byteSize) {
      buffers.push(secret)
      bufSize += secret.length
    }
    const repeat = bufSize % byteSize
    if (repeat !== 0) {
      buffers.push(secret.slice(0, repeat))
    }
    secret = Buffer.concat(buffers, bufSize)
  }

  return secret
}

/**
 * Generate a base32-encoded random secret.
 *
 * @param {number} [byteSize=20] Number of random bytes to generate for secret.
 * @param {string} [encoding="base32"] Encoding for returned secret.
 * @return {string} The generated secret.
 */
export function generateSecret(byteSize=20, encoding='base32'): string {
  const bytes: Buffer = crypto.randomBytes(byteSize)
  if (encoding === 'base32') {
    return base32.encode(bytes).replace(/=/g, '')
  } else {
    return bytes.toString(encoding)
  }
}

/**
 * Hash-based one-time (HOTP) password.
 */
export class HOTP {
  public readonly type: string = 'hotp'

  public secret: Buffer
  public encoding: string
  public counter: number

  public digits: number
  public window: number
  public period: number

  public _algorithm: string
  public get algorithm() { return this._algorithm }
  public set algorithm(value: string) { this._algorithm = value.toUpperCase() }

  public label: string
  public issuer: string

  public _required: string[]
  public _optional: string[]

  private _digitsFactor: number
  private _digitsPadding: string
  private _secretByteSize: number
  private _paddedSecret: Buffer

  /**
   * Constructor.
   *
   * @param {Object} params
   * @param {Buffer|string} params.secret Shared secret
   * @param {string} [params.encoding="ascii"] Secret encoding (ascii, hex,
   *   base32, base64). Only used if `params.secret` is not a `Buffer`.
   * @param {number} [params.counter=0] Counter value
   * @param {number} [params.digits=6] The number of digits for the
   *   one-time code.
   * @param {number} [params.window=1] The allowable margin for the
   *   counter. {@link HOTP.diff}.
   * @param {string} [params.algorithm="SHA1"] Hash algorithm (SHA1,
   *   SHA256, SHA512).
   * @param {string} [params.label] Used for otpauth URL generation only.
   *   Identify the account with which the OTP secret is associated, e.g.
   *   the user's email address.
   * @param {string} [params.issuer] Used for otpauth URL generation only.
   *   The provider or service with which the OTP secret is associated.
   */
  constructor(params) {
    this.set(params)
  }

  public set(params): void {
    if (params) {

      // set required params
      this._required.forEach((key) => {
        const value = params[key]
        if (value == null) {
          throw new Error('missing ' + key)
        }
        this[key] = value
      })

      // set optional params only if unset to allow use of prototypical
      // inheritance for default values
      this._optional.forEach((key) => {
        const value = params[key]
        if (value != null) {
          this[key] = value
        }
      })

    } else if (this._required.length !== 0) {
      throw new Error('missing ' + this._required[0])
    }

    if (!Buffer.isBuffer(this.secret)) {
      if (this.encoding === 'base32') {
          this.secret = new Buffer(base32.decode(this.secret))
      } else {
          this.secret = new Buffer(this.secret, this.encoding);
      }
    }

    this._digitsFactor = Math.pow(10, this.digits)
    this._digitsPadding = new Array(this.digits + 1).join('0')
  }

  /**
   * Digest the HOTP token.
   *
   * @return {Buffer} The HOTP token as a buffer.
   */
  public digest(): Buffer {
    // create a buffer from the counter
    const buf = new Buffer(8)
    let tmp = this.counter
    for (let i = 0; i < 8; ++i) {
      // mask 0xff over number to get last 8
      buf[7 - i] = tmp & 0xff

      // shift 8 and get ready to loop over the next batch of 8
      tmp = tmp >> 8
    }

    if (!this._paddedSecret) {
      const byteSize = _getSecretByteSize(this.algorithm)
      if (this.secret.length < byteSize) {
        console.warn('libotp: HMAC key repeated to ' + byteSize + 'bytes;' +
                     ' compatibility could be improved by using a secret' +
                     ' with a byte size of ' + byteSize + '.')
        this._paddedSecret = _getPaddedSecret(this.secret, byteSize)
      } else {
        this._paddedSecret = this.secret
      }
    }

    // return hmac digest buffer
    const hmac = crypto.createHmac(this.algorithm, this._paddedSecret)
    hmac.update(buf)
    return hmac.digest()
  }

  /**
   * Get the HOTP token as an integer, without incrementing the counter.
   *
   * @return {number} The HOTP token.
   */
  public peekInt(): number {
    // digest the params
    const digest = this.digest()

    // compute HOTP offset
    const offset = digest[digest.length - 1] & 0xf

    // calculate binary code (RFC4226 5.4)
    const code = (digest[offset] & 0x7f) << 24 |
      (digest[offset + 1] & 0xff) << 16 |
      (digest[offset + 2] & 0xff) << 8 |
      (digest[offset + 3] & 0xff)

    return code % this._digitsFactor
  }

  /**
   * Get the HOTP token as a zero-padded string, without incrementing the
   * counter.
   *
   * @return {number} The HOTP token.
   */
  public peek(): string {
    // left-pad token
    const token = this._digitsPadding + this.peekInt().toString(10)
    return token.substr(-this.digits)
  }

  /**
   * Generate a HOTP token, incrementing the counter value.
   *
   * The `this.counter` value is incremented by 1 after the token is
   * generated. The new counter value must be stored in durable storage,
   * with conflicting updates resolving to the largest counter value.
   *
   * @return {string} The TOTP token.
   */
  public next(): string {
    const token = this.peek()
    this.counter++
    return token
  }

  /**
   * Calculate the difference with the given HOTP token.
   *
   * The token is valid if it matches a generated code in the range
   * `[C - W, C + W)` where `C` is the counter value and `W` is the window
   * size. `C - W` is included in the range, while `C + W` is excluded.
   *
   * @param {string} token The other OTP token
   * @return {number} If the token is valid,
   *   `(counter value for token) - this.counter`, or `NaN` otherwise.
   */
  public diff(token: string): number {
    // fail if token is not of correct length
    if (!token || token.length !== this.digits) {
      return NaN
    }

    // parse token to number or fail
    const code = parseInt(token, 10)
    if (isNaN(code)) {
      return NaN
    }

    // short path for no window
    if (this.window === 0) {
      return this.peekInt() === code ? 0 : NaN
    }

    // shadow options
    let self = new HOTP(this);

    // loop in [C - W, C + W)
    const limit = self.counter + this.window
    for (let i = this.counter - this.window; i < limit; i++) {
      self.counter = i
      if (self.peekInt() === code) {
        // found a matching code, return delta
        return i - this.counter
      }
    }

    // no codes have matched
    return NaN
  }

  /**
   * Test if a HOTP token is valid.
   *
   * @param {string} Token to validate
   * @return {Boolean} True if the token is valid.
   */
  public test(token: string): boolean {
    return !isNaN(this.diff(token))
  }

  /**
   * Test if a HOTP token is valid, updating the instance counter as needed.
   *
   * @param {string} Token to validate
   * @return {Boolean} True if the token is valid.
   */
  public update(token: string): boolean {
    const delta = this.diff(token)
    if (delta < 0) {
      this.counter -= delta
    }
    return !isNaN(delta)
  }

  /**
   * Generate an otpauth URL compatible with Google Authenticator.
   *
   * The otpauth URL is used to pass the shared secret to a client device to
   * configure the OTP generator.
   *
   * Google Authenticator considers TOTP codes valid for 30 seconds.
   * Additionally, the app presents 6 digits codes to the user. According to
   * the documentation, the period and number of digits are currently
   * ignored by the app.
   *
   * To generate a suitable QR Code, pass the generated URL to a QR Code
   * generator, such as the `qr-image` module.
   *
   * @return {string} A URL suitable for use with the Google Authenticator.
   * @throws ImportError if the module `base32.js` is not available.
   * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
   */
  public url(): string {
    // unpack options
    const label = this.label
    const counter = this.counter

    // required options
    if (!this.label) {
      throw new Error('missing label')
    }

    // convert secret to base32
    const secret = base32.encode(this.secret)

    // build query
    const query = {secret: encodeURIComponent(secret)}

    // set issuer
    if (this.issuer) {
      query['issuer'] = encodeURIComponent(this.issuer)
    } else {
      console.warn('libotp: issuer is strongly recommended for otpauth URL')
    }
    // set counter if HOTP
    if (this.type === 'hotp') {
      query['counter'] = this.counter
    }

    // set algorithm
    if (this.algorithm !== 'SHA1') {
      console.warn('libotp: otpauth URL compatibility could be improved ' +
                   'by using the default algorithm of SHA1')
      query['algorithm'] = this.algorithm
    }

    // set digits
    if (this.digits !== 6) {
      console.warn('libotp: otpauth URL compatibility could be improved ' +
                   'by using the default digits of 6')
      query['digits'] = this.digits
    }

    // set period
    if (this.type === 'totp') {
      if (this.period !== 30) {
        console.warn('libotp: otpauth URL compatibility could be improved ' +
                     'by using the default period of 30 seconds')
        query['period'] = this.period
      }
    } else if (this.type !== 'hotp') {
      throw new Error('invalid type `' + this.type + '`')
    }

    // return url
    return url.format({
      protocol: 'otpauth',
      hostname: this.type,
      pathname: encodeURIComponent(this.label),
      query,
      slashes: true
    })
  }
}

// set defaults
HOTP.prototype.encoding = 'ascii'
HOTP.prototype.digits = 6
HOTP.prototype.window = 1
HOTP.prototype._algorithm = 'SHA1'
HOTP.prototype._required = ['secret', 'counter']
HOTP.prototype._optional = ['digits', 'encoding', 'algorithm', 'window',
                            'label', 'issuer']

/**
 * Time-based one-time (TOTP) password.
 *
 * By default, the TOTP generated tokens are verified with time period of 30
 * seconds and a window size of 1, meaning a token is valid for up to 59s.
 *
 * A time period of 30 seconds with a window size of 1 results in a token
 * that is valid for up to 59s due to client time drift. For example:
 *
 * - Configuration: period=30 window=1
 * - Server: time(s)=120 counter=`Math.floor(120/period)`=4
 * - Client: time(s)=149 counter=`Math.floor(149/period)`=4
 * - Counter difference: `4 - 4 = 0` (valid)
 * - Time difference: `149 - 120 = 29` (29s)
 *
 * - Configuration: period=30 window=1
 * - Server: time(s)=120 counter=`Math.floor(120/period)`=4
 * - Client: time(s)=90 counter=`Math.floor(179/period)`=3
 * - Counter difference: `3 - 4 = -1` (valid)
 * - Time difference: `90 - 120 = -30` (-30s)
 *
 * You can specify a window and time period to change the tolerance to time
 * drift during verification. The maximum tolerable time drift in
 * seconds is calculated as:
 *
 * ```
 * tolerance = (window + 1) * period - 1
 * ```
 *
 * *Usage*
 *
 * ```js
 * var crypto = require('crypto');
 * var secret = crypto.randomBytes(20);
 *
 * // with default options
 * var otp = new TOTP({secret: secret});
 * var token = otp.next();
 * var isValid = otp.test(token);
 *
 * // with custom window and time period
 * var otp = new TOTP({secret: secret, window: 1, period: 60});
 * ```
 */
export class TOTP extends HOTP {
  public readonly type: string = 'totp'

  public time: number|(() => number)
  public epoch: number
  // public period: number

  public _required: string[]
  public _optional: string[]

  /**
   * Constructor.
   *
   * @method constructor
   * @param {Buffer} params.secret Shared secret
   * @param {Buffer|string} params.secret Shared secret
   * @param {string} [params.encoding="ascii"] Secret encoding (ascii, hex,
   *   base32, base64). Only used if `params.secret` is not a `Buffer`.
   * @param {number} [params.counter=0] Counter value
   * @param {number} [params.digits=6] The number of digits for the
   *   one-time code.
   * @param {number} [params.window=1] The allowable margin for the
   *   counter. {@link HOTP.diff}.
   * @param {string} [params.algorithm="sha1"] Hash algorithm (sha1,
   *   sha256, sha512).
   * @param {string} [params.label] Used for otpauth URL generation only.
   *   Identify the account with which the OTP secret is associated, e.g.
   *   the user's email address.
   * @param {string} [params.issuer] Used for otpauth URL generation only.
   *   The provider or service with which the OTP secret is associated.
   * @param {number} [params.time=(() => Date.now() / 1000)] Function or
   *   number returning time in seconds with which to calculate counter
   *   value. Defaults to `Date.now`.
   * @param {number} [params.epoch=0] Initial seconds since the UNIX
   *   epoch from which to calculate the counter value. Defaults to 0
   *   (no offset).
   * @param {number} [params.period=30] Time period in seconds
   * @param {string} [params.label] Used for otpauth URL generation only.
   *   Identify the account with which the OTP secret is associated, e.g.
   *   the user's email address.
   * @param {string} [params.issuer] Used for otpauth URL generation only.
   *   The provider or service with which the OTP secret is associated.
   */

  /**
   * Calculate counter value.
   *
   * A counter value converts a TOTP time into a counter value by
   * calculating the number of time periods that have passed since
   * `this.epoch`.
   *
   * ```
   * counter = Math.floor((this.time() - this.epoch) / this.period)
   * ```
   */
  public get counter(): number {
    const time = typeof this.time === 'function' ? this.time() : this.time
    return Math.floor((time - this.epoch) / this.period)
  }

  public set(params) {
    super.set(params)
    if (this.period <= 0) {
      throw new Error('params.period <= 0')
    } else if (this.period !== 30) {
      console.warn('libotp: compatibility could be improved by setting' +
                   ' period = 30')
    }
  }
}

// set defaults
TOTP.prototype._required = HOTP.prototype._required.filter((s) => s !== 'counter')
TOTP.prototype._optional = HOTP.prototype._optional.concat(['time', 'period', 'epoch'])
TOTP.prototype.time = () => Date.now() / 1000
TOTP.prototype.epoch = 0
TOTP.prototype.period = 30
TOTP.prototype.next = TOTP.prototype.peek
