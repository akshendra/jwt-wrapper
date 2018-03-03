
const { expect } = require('chai');
const JWT = require('./index');
const jwt = new JWT({
  secret: 'mine',
});
const state = {};

function wait(time) {
  return new Promise(resolve => {
    setTimeout(resolve, time);
  });
}

describe('JWT', () => {
  it('should create a token', () => {
    return jwt.create({
      val: 1,
    }, {
      expiresIn: '1s',
    }).then(token => {
      state.token = token;
    });
  });

  it('should verify the token', () => {
    return jwt.verify(state.token)
      .then(decoded => {
        return expect(decoded.val).to.deep.equal(1);
      });
  });

  it('should have expired afetr 1 sec', () => {
    return wait(1000)
      .then(() => {
        return jwt.verify(state.token);
      })
      .catch(err => {
        if (err.message !== 'Token is expired') {
          throw err;
        }
      });
  });
});
