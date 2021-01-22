const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');
const AppError = require('../utils/appError');

const passwordRegExTest = function (password) {
  //RegEx for testing passwords to have at least eight characters containing at least one uppercase letter, one lowercase letter, one number, and one symbol.
  const passwordRegEx = /(?=.{8,})(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[-~!@#$%^&*()_=+`|{}'".,:;?<>\\/[\]])/;
  return passwordRegEx.test(password);
};

const validateConfirmPassword = function (confirmPassword) {
  return this.password === confirmPassword;
};

const createValidationError = function (err, doc, next) {
  if (err) return next(new AppError(err.message, 400));
  next();
};

const hashPassword = async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 12);
  this.passwordChangeDate = Date.now() - 1000; // A one second error margin for letting data to be saved on database.
  this.confirmPassword = undefined;
  next();
};

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
    required: [true, 'Password is required.'],
    validate: [
      passwordRegExTest,
      'Password should have at least eight characters containing at least one uppercase letter, one lowercase letter, one number, and one symbol.',
    ],
  },
  confirmPassword: {
    type: String,
    required: [true, 'Enter your password again.'],
    validate: [validateConfirmPassword, 'Passwords do not match.'],
  },
  passwordChangeDate: Date,
});

userSchema.post('validate', createValidationError);

userSchema.pre('save', hashPassword);

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.changedPasswordAfterToken = function (JWTTimeStamp) {
  return this.passwordChangeDate.getTime() > 1000 * JWTTimeStamp;
};

const User = mongoose.model('user', userSchema);

module.exports = {
  User,
  hashPassword,
  createValidationError,
  passwordRegExTest,
  validateConfirmPassword,
};
