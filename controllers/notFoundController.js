const AppError = require('../utils/appError');

module.exports = (req, res, next) => {
  return next(new AppError('Could not find the requested URL.', 404));
};
