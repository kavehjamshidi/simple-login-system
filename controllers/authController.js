const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const User = require('../models/userModel');
const catchAsyncError = require('../middlewares/catchAsyncError');
const AppError = require('../utils/appError');

function signToken(id) {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRATION,
  });
}

module.exports.signUp = catchAsyncError(async (req, res) => {
  let newUser = await User.create({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
  });

  const token = signToken(newUser._id);

  newUser = {
    username: newUser.username,
    email: newUser.email,
  };

  return res.status(201).json({
    status: 'success',
    token,
    data: {
      user: newUser,
    },
  });
});

module.exports.login = catchAsyncError(async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return next(new AppError('Please provide email and password.', 400));
  }

  const user = await User.findOne({ username });

  if (!user || !(await user.comparePassword(password))) {
    return next(new AppError('Incorrect username or password.', 401));
  }

  const token = signToken(user._id);
  res.status(200).json({
    status: 'success',
    token,
  });
});

module.exports.protect = catchAsyncError(async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(new AppError('You are not logged in.', 401));
  }

  const decodedPayload = await promisify(jwt.verify)(
    token,
    process.env.JWT_SECRET
  );

  const user = await User.findById(decodedPayload.id);
  if (!user) return next(new AppError('The user no longer exists', 401));

  if (user.changedPasswordAfterToken(decodedPayload.iat))
    return next(
      new AppError('Login credentials have changed. Please login again.', 401)
    );

  // For other middlewares, mainly authorization.
  req.user = user;
  next();
});
