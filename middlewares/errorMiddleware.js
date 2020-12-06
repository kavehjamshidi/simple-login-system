module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  return res.status(err.statusCode).json({
    status: 'error',
    message: err.message,
    stack: err.stack,
  });
};
