const AppError = require('../utils/appError');
const logger = require('../utils/logger');

function handleJWTError() {
  return new AppError('Invalid token.', 401);
}

function handleJWTExpiredError() {
  return new AppError('Your token has expired.', 401);
}

function handleMongooseDuplicateError(field) {
  return new AppError(`An account with this ${field} already exists.`, 400);
}

module.exports = (err, req, res, next) => {
  if (err.name === 'JsonWebToken' || err.name === 'JsonWebTokenError')
    err = handleJWTError();
  if (err.name === 'TokenExpiredError') err = handleJWTExpiredError();
  if (err.code === 11000)
    err = handleMongooseDuplicateError(...Object.keys(err.keyPattern));

  logger.error(err.message, err);
  err.statusCode = err.statusCode || 500;

  if (err.statusCode === 500 && !(err instanceof AppError))
    err.message = 'Something went wrong.';

  return res.status(err.statusCode).json({
    status: 'error',
    message: err.message,
  });
};
