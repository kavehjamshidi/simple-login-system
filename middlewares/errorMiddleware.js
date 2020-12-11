const AppError = require('../utils/appError');
const logger = require('../utils/logger');

function handleJWTError() {
  return new AppError('Invalid token. Please login again.', 401);
}

function handleJWTExpiredError() {
  return new AppError('You token has expired. Please login again.', 401);
}

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;

  if (err.name === 'JsonWebToken') err = handleJWTError();
  if (err.name === 'TokenExpiredError') err = handleJWTExpiredError();

  logger.error(err.message, err);

  return res.status(err.statusCode).json({
    status: 'error',
    message: err.message,
    stack: err.stack,
  });
};
