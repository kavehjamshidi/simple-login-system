const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const crypto = require('crypto');
const { User } = require('../models/userModel');
const catchAsyncError = require('../middlewares/catchAsyncError');
const AppError = require('../utils/appError');
const sendEmail = require('../utils/email');

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
  return res.status(200).json({
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

module.exports.forgotPassword = catchAsyncError(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user)
    return next(new AppError('No user found with the provided email.', 404));

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  const resetUrl = `${req.protocol}://${req.get(
    'host'
  )}/user/resetPassword/${resetToken}`;
  const message = `You can reset your password via this link: 
  ${resetUrl}
  This link is valid only for 15 minutes.`;

  try {
    await sendEmail({ email: user.email, subject: 'Password reset', message });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpired = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError('There was an error sending the email. Try again later', 500)
    );
  }

  return res.status(200).json({
    status: 'success',
    message:
      'A link with instructions to reset your password has been sent to your email address.',
  });
});

module.exports.resetPassword = catchAsyncError(async (req, res, next) => {
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpired: { $gt: Date.now() },
  });
  if (!user) return next(new AppError('Invalid token', 400));

  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  user.passwordResetToken = undefined;
  user.passwordResetExpired = undefined;
  await user.save();

  return res.status(200).json({
    status: 'success',
    message:
      'Password updated successfully. You can login with your new credentials.',
  });
});
