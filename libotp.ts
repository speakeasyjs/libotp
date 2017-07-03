'use strict'

import * as base32 from 'base32.js'
import * as crypto from 'crypto'
import * as _debug from 'debug'
import * as url from 'url'

const debug = _debug('libotp')

function checkWindow(window): number {
  if (Math.floor(window) !== window) {
    throw new Error('Invalid window `' + window + '`')
  }
  return window
}

function checkDigits(digits): number {
  if (Math.floor(digits) !== digits) {
    throw new Error('Invalid digits `' + digits + '`')
  } else if (digits !== 6) {
    debug('Compatibility could be improved by using the default digits of 6.')
  }
  return digits
}

function checkAlgorithm(algorithm): string {
  algorithm = algorithm.toLowerCase()
  if (algorithm !== 'sha1') {
    debug('Compatibility could be improved by using the default algorithm' +
          ' of sha1.')
  }
  return algorithm
}

function checkCounter(counter): number {
  if (counter == null) {
    throw new Error('Missing counter value')
  }
  if (Math.floor(counter) !== counter) {
    throw new Error('Invalid counter `' + counter + '`')
  }
  return counter
}

function checkTime(time: Date|number|(() => Date|number)): number|(() => number) {
  if (typeof time === 'function') {
    const fn: (() => any) = time
    time = fn()
    if (time instanceof Date) {
      return () => Math.floor(fn() / 1000)
    } else if (typeof time === 'number') {
      return () => Math.floor(fn())
    }
  } else if (time instanceof Date) {
    return +time / 1000
  } else if (typeof time === 'number') {
    return Math.floor(<number>time)
  }
  throw new Error('invalid time ' + time)
}

function checkEpoch(epoch): number {
  if (Math.floor(epoch) !== epoch) {
    throw new Error('Invalid epoch `' + epoch + '`')
  }
  return epoch
}

function checkPeriod(period): number {
  if (Math.floor(period) !== period || period <= 0) {
    throw new Error('Invalid period `' + period + '`')
  } else if (period !== 30) {
    debug('Compatibility could be improved by using the default period' +
          ' of 30 seconds.')
  }
  return period
}

function byteSizeForAlgo(algorithm: string): number {
  switch (algorithm) {
    case 'sha1':
      return 20
    case 'sha256':
      return 32
    case 'sha512':
      return 64
    default:
      throw new Error('Unrecognized hash algorithm `' + algorithm + '`')
  }
}

function padSecret(secret: Buffer, byteSize: number): Buffer {
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
 * @param {number} [algorithm=sha1] Algorithm for which to generate secret.
 * @param {string} [encoding="base32"] Encoding for returned secret. Set to
 *   falsy for Buffer.
 * @return {string} The generated secret.
 */
export function generateSecret(algorithm='sha1', encoding='base32'): string|Buffer {
  const byteSize = byteSizeForAlgo(algorithm)
  const bytes: Buffer = crypto.randomBytes(byteSize)
  if (encoding === 'base32') {
    return base32.encode(bytes).replace(/=/g, '')
  } else if (!encoding) {
    return bytes
  } else {
    return bytes.toString(encoding)
  }
}

/**
 * Base parameters.
 *
 * OTP parameters:
 * - `digits=6`: The number of digits for the one-time password. Used when
 *   generating one-time passwords.
 *
 * Secret parameters:
 *
 * - `secret`: Required. The shared secret as a Buffer or string. Used when
 *   generating and validating one-time passwords.
 * - `encoding=ascii`: The string encoding for the string secret. Used if
 *   the shared secret is a string. Ignored if shared secret is a buffer.
 *
 * Cryptographic parameters:
 * - `algorithm=sha1`: The hash algorithm. Used when generating one-time
 *   passwords. For maximum compatibility, use the default of `sha1`.
 *
 * Provider parameters:
 * - `label`: The label to display in client apps, e.g. email address. Used
 *   when generating Google Authenticator compatible URLs.
 * - `issuer`: The issuer to display in client apps, e.g. website name. Used
 *   when generating Google Authenticator compatible URLs.
 */
interface BaseParams {
  secret: Buffer|string
  encoding?: 'ascii' | 'hex' | 'base32' | 'base64' | string

  digits?: number
  window?: number

  algorithm?: 'sha1' | 'sha256' | 'sha512' | string

  label?: string
  issuer?: string
}

/**
 * HOTP parameters.
 *
 * HOTP parameters:
 * - `window=1`: The validation window. Used when validating hash-based
 *   one-time passwords. A one-time password is valid if it represents a
 *   counter value within `[counter, counter + window)`, where
 *   `[counter` is the inclusive minimum value accepted and
 *   `counter + window)` is the exclusive maximum value accepted.
 */
export interface HOTPParams extends BaseParams {
  counter: number
}

/**
 * TOTP parameters.
 *
 * TOTP parameters:
 * - `window=1`: The validation window. Used when validating time-based
 *   one-time passwords. A one-time password is valid if it represents a
 *   time step value within `[counter - window, counter + window)`, where
 *   `[counter - window` is the inclusive minimum server value accepted and
 *   `counter + window)` is the exclusive maximum server value accepted.
 * - `time=() => Date.now()/1000`: A function returning the current number
 *   of seconds since the UNIX epoch.
 * - `epoch=0`: The time offset in seconds since the UNIX epoch to use.
 * - `period=30`: The time period. Used to divide the current time into
 *   time steps.
 */
export interface TOTPParams extends BaseParams {
  time?: Date|number|(() => Date|number)
  epoch?: number
  period?: number
}

/**
 * One-time password.
 */
abstract class OTP {
  public readonly type: string

  public readonly secret: Buffer|string
  public readonly encoding: string

  public abstract get counter(): number

  public readonly digits: number = 6
  public readonly window: number = 1

  public readonly algorithm: string = 'sha1'

  public readonly label: string
  public readonly issuer: string

  protected _modulo: number
  protected _padding: string
  protected _secret: Buffer
  protected _padded: Buffer

  /**
   * Constructor.
   *
   * @param {BaseParams} params
   */
  constructor(params: BaseParams) {
    // required parameters
    if (!params) throw new Error('Missing parameters')
    if (!params.secret) throw new Error('Missing secret value')

    // check secret
    this.secret = params.secret
    if (!Buffer.isBuffer(params.secret)) {
      if (!params.encoding) {
        debug('A string secret was provided without an encoding. Consider' +
              ' providing a Buffer secret or the string encoding.')
      } else {
        this.encoding = params.encoding
      }
    }

    if (params.digits) this.digits = checkDigits(params.digits)
    if (params.window) this.window = checkWindow(params.window)
    if (params.algorithm) this.algorithm = checkAlgorithm(params.algorithm)
    if (params.label) this.label = params.label
    if (params.issuer) this.issuer = params.issuer

    this._modulo = Math.pow(10, this.digits)
    this._padding = new Array(this.digits + 1).join('0')
  }

  protected _getSecret(): Buffer {
    if (this._secret) return this._padded

    let secret, padded

    // Parse secret into Buffer.
    if (Buffer.isBuffer(this.secret)) {
      secret = this.secret
    } else if (this.encoding === 'base32') {
      secret = new Buffer(base32.decode(this.secret))
    } else {
      secret = new Buffer(this.secret, this.encoding || 'ascii');
    }

    // Pad secret.
    const byteSize = byteSizeForAlgo(this.algorithm)
    if (secret.length < byteSize) {
      debug('HMAC key repeated to %d bytes. Compatibility could be' +
            ' improved by using a secret with a byte size of %d.',
            byteSize, byteSize)
      padded = padSecret(secret, byteSize)
    }

    this._secret = secret
    this._padded = padded || secret

    return this._padded
  }

  /**
   * Digest the OTP token.
   *
   * @return {Buffer} The OTP token as a buffer.
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

    // return hmac digest buffer
    const hmac = crypto.createHmac(this.algorithm, this._getSecret())
    hmac.update(buf)
    return hmac.digest()
  }

  /**
   * Get the OTP token as an integer, without incrementing the counter.
   *
   * @return {number} The OTP token.
   */
  public code(): number {
    // digest the params
    const digest = this.digest()

    // compute OTP offset
    const offset = digest[digest.length - 1] & 0xf

    // calculate binary code (RFC4226 5.4)
    const code = (digest[offset] & 0x7f) << 24 |
      (digest[offset + 1] & 0xff) << 16 |
      (digest[offset + 2] & 0xff) << 8 |
      (digest[offset + 3] & 0xff)

    return code % this._modulo
  }

  /**
   * Get the OTP token as a zero-padded string, without incrementing the
   * counter.
   *
   * @return {number} The OTP token.
   */
  public token(): string {
    // left-pad token
    const token = this._padding + this.code().toString(10)
    return token.substr(-this.digits)
  }

  /**
   * Calculate the difference with the given OTP token.
   *
   * The token is valid if it matches a generated code in the range
   * `[C - W, C + W)` where `C` is the counter value and `W` is the window
   * size. `C - W` is included in the range, while `C + W` is excluded.
   *
   * @param {string} token The other OTP token
   * @return {number} If the token is valid,
   *   `(counter value for token) - this.counter`, or `false` otherwise.
   */
  public diff(token: string): number|false {
    // fail if token is not of correct length
    if (!token || token.length !== this.digits) {
      return false
    }

    // parse token to number or fail
    const code = parseInt(token, 10)
    if (isNaN(code)) {
      return false
    }

    // short path for no window
    if (this.window === 0) {
      return this.code() === code ? 0 : false
    }

    // loop in [C, C + W) or [C - W, C + W)
    let i = this.counter;
    if (this instanceof TOTP) i -= this.window;
    const limit = this.counter + this.window

    // proxy self
    function Proxy() {}
    Proxy.prototype = this
    let self = new Proxy()
    Object.defineProperty(self, 'counter', { get: () => i })

    for (; i < limit; i++) {
      if (self.code() === code) {
        // found a matching code, return delta
        return i - this.counter
      }
    }

    // no codes have matched
    return false
  }

  /**
   * Test if a OTP token is valid.
   *
   * @param {string} Token to validate
   * @return {Boolean} True if the token is valid.
   */
  public test(token: string): boolean {
    return this.diff(token) !== false
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
    if (!this.label) throw new Error('Missing label value')

    // convert secret to base32
    this._getSecret()
    const secret = base32.encode(this._secret)

    // build query
    const query = {secret: encodeURIComponent(secret)}

    // set issuer
    if (this.issuer) {
      query['issuer'] = encodeURIComponent(this.issuer)
    } else {
      debug('Providing an issuer is strongly recommended for otpauth URL.')
    }

    // set counter if HOTP
    if (this instanceof HOTP) {
      query['counter'] = this.counter
    }

    // set algorithm
    if (this.algorithm !== 'sha1') {
      query['algorithm'] = this.algorithm.toUpperCase()
    }

    // set digits
    if (this.digits !== 6) {
      query['digits'] = this.digits
    }

    // set period
    if (this instanceof TOTP && this.period !== 30) {
      query['period'] = this.period
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

/**
 * Hash-based one-time (HOTP) password.
 *
 * *Usage*
 *
 * ```js
 * var libotp = require('libotp')
 * var secret = libotp.generateSecret()
 *
 * var params = { secret: secret, counter: 0 }
 * var client = new libotp.HOTP(params)
 * var server = new libotp.HOTP(params)
 *
 * // generate token on client
 * var token = client.token()
 *
 * // validate token on server
 * if (server.test(token)) {
 *   // Token is valid.
 *   var counter = server.next()
 *   // Important: persist counter value here.
 * } else {
 *   // Token is invalid.
 * }
 */
export class HOTP extends OTP {
  public readonly type: string = 'hotp'
  public counter: number

  /**
   * Constructor.
   *
   * @param {HOTPParams} params
   * @param {Buffer|string} params.secret Shared secret
   * @param {string} [params.encoding="ascii"] Secret encoding (ascii, hex,
   *   base32, base64). Only used if `params.secret` is not a `Buffer`.
   * @param {number} params.counter Counter value
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
  constructor(params: HOTPParams) {
    super(params)
    this.counter = checkCounter(params.counter)
  }

  /**
   * Increment the counter value.
   *
   * The new counter value must be stored in durable storage, with
   * conflicting updates resolving to the largest counter value.
   *
   * @return {number} The counter value.
   */
  public next(): number {
    return ++this.counter
  }

  /**
   * Test if a HOTP token is valid, updating the instance counter as needed.
   *
   * @param {string} Token to validate
   * @return {Boolean} True if the token is valid.
   */
  public update(token: string): boolean {
    const delta = this.diff(token)
    const ok = delta !== false
    if (ok && delta > 0) {
      this.counter += <number>delta
    }
    return ok
  }
}

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
 * var libotp = require('libotp')
 * var secret = libotp.generateSecret()
 *
 * // with default options
 * var params = { secret: secret }
 * var client = new libotp.TOTP(params)
 * var server = new libotp.TOTP(params)
 *
 * // with custom window and time period
 * var params = { secret: secret, window: 1, period: 60 }
 * var client = new libotp.TOTP(params)
 * var server = new libotp.TOTP(params)
 *
 * // generate token on client
 * var token = client.token()
 *
 * // validate token on server
 * if (server.test(token)) {
 *   // Token is valid.
 * } else {
 *   // Token is invalid.
 * }
 * ```
 */
export class TOTP extends OTP {
  public readonly type: string = 'totp'

  public time: number|(() => number) = () => Date.now() / 1000
  public epoch: number = 0
  public period: number = 30

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
  constructor(params: TOTPParams) {
    super(params)
    if (params.time) this.time = checkTime(params.time)
    if (params.epoch) this.epoch = checkEpoch(params.epoch)
    if (params.period) this.period = checkPeriod(params.period)
  }

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
}
