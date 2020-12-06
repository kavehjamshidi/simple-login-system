const jwt = require('jsonwebtoken');
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
