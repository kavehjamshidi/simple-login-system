const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const crypto = require('crypto');
const validator = require('validator');
const { User } = require('../models/userModel');
const catchAsyncError = require('../middlewares/catchAsyncError');
const AppError = require('../utils/appError');
const sendEmail = require('../utils/email');
const redisClient = require('../utils/cache');

jwt.verify = promisify(jwt.verify);

module.exports.signUp = catchAsyncError(async (req, res) => {
  let user = await User.create({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
  });

  const jwtid = crypto.randomBytes(16).toString('hex');
  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    issuer: 'access',
    expiresIn: 300,
    jwtid,
  });

  const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    issuer: 'refresh',
    expiresIn: '7d',
    jwtid,
  });

  user = {
    username: user.username,
    email: user.email,
  };

  return res.status(201).json({
    status: 'success',
    data: {
      user,
      accessToken,
      refreshToken,
    },
  });
});

module.exports.login = catchAsyncError(async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return next(new AppError('Please enter email and password.', 400));
  }

  const user = await User.findOne({ username });

  if (!user || !(await user.comparePassword(password))) {
    return next(new AppError('Invalid username or password.', 401));
  }

  const jwtid = crypto.randomBytes(16).toString('hex');
  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    issuer: 'access',
    expiresIn: 300,
    jwtid,
  });

  const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    issuer: 'refresh',
    expiresIn: '7d',
    jwtid,
  });

  return res.status(200).json({
    status: 'success',
    data: {
      accessToken,
      refreshToken,
    },
  });
});

module.exports.protect = catchAsyncError(async (req, res, next) => {
  if (
    !req.headers.authorization ||
    !req.headers.authorization.startsWith('Bearer ')
  ) {
    return next(new AppError('You are not logged in.', 401));
  }

  const accessToken = req.headers.authorization.split(' ')[1];

  const payload = await jwt.verify(accessToken, process.env.JWT_SECRET, {
    issuer: 'access',
  });

  if (await redisClient.get(payload.jti))
    return next(new AppError('Access forbidden.', 403));

  const user = await User.findById(payload.id);
  if (!user) return next(new AppError('User not found.', 401));

  if (user.changedPasswordAfterToken(payload.iat))
    return next(
      new AppError('Login credentials have changed. Please login again.', 401)
    );

  // For other middlewares, mainly authorization.
  req.user = user;
  next();
});

module.exports.refresh = catchAsyncError(async (req, res, next) => {
  if (
    !req.headers.authorization ||
    !req.headers.authorization.startsWith('Bearer ')
  ) {
    return next(new AppError('You are not logged in.', 401));
  }

  const refreshToken = req.headers.authorization.split(' ')[1];
  const payload = await jwt.verify(refreshToken, process.env.JWT_SECRET, {
    issuer: 'refresh',
  });

  if (await redisClient.get(payload.jti))
    return next(new AppError('Access forbidden.', 403));

  const user = await User.findById(payload.id);
  if (!user) return next(new AppError('User not found.', 401));

  if (user.changedPasswordAfterToken(payload.iat))
    return next(
      new AppError('Login credentials have changed. Please login again.', 401)
    );

  const jwtid = crypto.randomBytes(16).toString('hex');
  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    issuer: 'access',
    expiresIn: 300,
    jwtid,
  });
  const newRefreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    issuer: 'refresh',
    expiresIn: '7d',
    jwtid,
  });

  await redisClient.set(payload.jti, payload.id);
  await redisClient.expire(
    payload.jti,
    payload.exp - parseInt(Date.now() / 1000, 10)
  );

  res.status(200).json({
    status: 'success',
    data: {
      accessToken,
      refreshToken: newRefreshToken,
    },
  });
});

module.exports.forgotPassword = catchAsyncError(async (req, res, next) => {
  const { email } = req.body;
  if (!email) {
    return next(new AppError('Please enter your email.', 400));
  }

  if (!validator.isEmail(email))
    return next(new AppError('Invalid email.', 400));

  const user = await User.findOne({ email });
  if (!user)
    return next(new AppError('No user found with the provided email.', 404));

  const resetToken = crypto.randomBytes(64).toString('hex');

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
      new AppError('There was an error sending the email. Try again later', 502)
    );
  }

  await redisClient.set(resetToken, email);
  await redisClient.expire(email, 900);

  return res.status(200).json({
    status: 'success',
    message:
      'A link with instructions to reset your password has been sent to your email address.',
  });
});

module.exports.resetPassword = catchAsyncError(async (req, res, next) => {
  const email = await redisClient.get(req.params.token);

  if (!email) return next(new AppError('Invalid reset token.', 400));

  const user = await User.findOne({ email });
  if (!user) return next(new AppError('Invalid reset token.', 400));

  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  user.passwordChangeDate = new Date();

  await user.save();
  await redisClient.del(req.params.token);

  return res.status(200).json({
    status: 'success',
    message:
      'Password updated successfully. You can login with your new credentials.',
  });
});
