const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const AppError = require('../utils/appError');

//RegEx for testing passwords to have at least eight characters containing at least one uppercase letter, one lowercase letter, one number, and one symbol.
const passwordRegEx = /(?=.{8,})(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[-~!@#$%^&*()_=+`|{}'".,:;?<>\\/[\]])/;

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required.'],
    minlength: 1,
    maxlength: 16,
    unique: true,
    trim: true,
  },
  email: {
    type: String,
    required: [true, 'Email is required.'],
    unique: true,
    trim: true,
    lowercase: true,
    validate: [validator.isEmail, 'Invalid email.'],
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    validate: {
      validator: function (field) {
        return passwordRegEx.test(field);
      },
      message:
        'Password should have at least eight characters containing at least one uppercase letter, one lowercase letter, one number, and one symbol.',
    },
  },
  confirmPassword: {
    type: String,
    required: [true, 'Enter your password again'],
    validate: {
      validator: function (field) {
        return this.password === field;
      },
      message: 'Passwords do not match.',
    },
  },
  passwordChangeDate: Date,
  passwordResetToken: String,
  passwordResetExpired: Date,
});

userSchema.post('validate', function (err, doc, next) {
  if (err) next(new AppError(err.message, 400));
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 12);
  this.passwordChangeDate = Date.now() - 1000; // A one second error margin for letting data to be saved on database.
  this.confirmPassword = undefined;
  next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.changedPasswordAfterToken = function (JWTTimeStamp) {
  if (this.passwordChangeDate)
    return this.passwordChangeDate.getTime() > 1000 * JWTTimeStamp;

  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  this.passwordResetExpired = Date.now() + 15 * 60 * 1000;

  return resetToken;
};

const User = mongoose.model('user', userSchema);

module.exports = User;
