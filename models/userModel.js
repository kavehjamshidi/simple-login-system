const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');
const AppError = require('../utils/appError');

//RegEx for testing passwords to have at least eight characters containing at least one uppercase letter, one lowercase letter, one number, and one symbol.
const passwordRegEx = /(?=.{8,})(?=.*[A-Z])(?=.*[a-z])(?=.*[1-9])(?=.*[-~@#$%^&*()_=+`|{}'".,:;?<>\\/[\]])/;

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
});

userSchema.post('validate', function (err, doc, next) {
  if (err) next(new AppError(err.message, 400));
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 12);
  this.confirmPassword = undefined;
  next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('user', userSchema);

module.exports = User;
