const mongoose = require('mongoose');
const crypto = require('crypto');

const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: true
  },
  name: {
    type: String,
    required: true
  },
  hash: String,
  salt: String
});

mongoose.model('User', userSchema);

userSchema.methods.setPassword = function (password) {
  this.salt = crypto.randomBytes(16).toString('hex');
  this.hash = crypto
    .pbkdf2Sync(password, this.salt, 1000, 64, 'sha512')
    .toString('hex');
};


userSchema.methods.validPassword = function (password) {
  const hash = crypto
    .pbkdf2Sync(password, this.salt, 1000, 64, 'sha512')
    .toString('hex');
  return this.hash === hash;
};


userSchema.method.generateJwt = function () {
  const expire = new Date();
  expire.setDate(expire.getDate() + 7);
  return jwt.sign({
    _id: this._id,
    name: this.name,
    email: this.email,
    exp: parseInt(expire.getTime() / 1000)
  }, 'MY SECRET');
  // DO NOT KEEP YOUR SECRET IN THE CODE!
  // Note: it’s important that your secret is kept safe: 
  // only the originating server should know what it is. 
  // It’s best practice to set the secret as an environment variable,
  //  and not have it in the source code, especially if your code is stored in version control somewhere.
}