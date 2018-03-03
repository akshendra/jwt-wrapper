
const jwt = require('jsonwebtoken');
const { validate, joi } = require('@akshendra/validator');

/**
 * @class JWT
 */
class JWT {
  constructor(config) {
    this.config = validate(config, joi.object().keys({
      algorithm: joi.string().default('HS256'),
      secret: joi.string().default('dirty leaves and dry grounds'),
    }));
  }

  /**
   * Create a jwt token
   *
   * @param {Object} data - to encode
   * @param {Object} [opts={}] - options for encoding
   *
   * @return {Promise<string, Error>} resolves to string token
   */
  create(data, opts) {
    const {
      algorithm,
      secret,
    } = this.config;
    opts = validate(opts, joi.object().keys({
      expiresIn: joi.string().default('1d'),
      algorithm: joi.string().default(algorithm),
      subject: joi.string(),
    }));

    return new Promise((resolve, reject) => {
      jwt.sign(data, secret, opts, (err, token) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(token);
      });
    });
  }

  /**
   * Decode and verfiy a jwt token
   *
   * @param {string} token - jwt token
   * @param {Object} [opts={}] - options for decoding
   *
   * @return {Promise<Object, Error>} resolves to json data
   */
  verify(token, opts) {
    const {
      algorithm,
      secret,
    } = this.config;
    opts = validate(opts, joi.object().keys({
      algorithm: joi.string().default(algorithm),
    }));

    return new Promise((resolve, reject) => {
      jwt.verify(token, secret, opts, (err, decoded) => {
        if (err) {
          if (err.name === 'TokenExpiredError') {
            const error = new Error('Token is expired');
            reject(error);
          } else if (err.name === 'JsonWebTokenError') {
            const error = new Error('Error parsing the token');
            reject(error);
          } else {
            reject(err);
          }
          return;
        }
        resolve(decoded);
      });
    });
  }
}

module.exports = JWT;
