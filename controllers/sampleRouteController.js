module.exports = (req, res) => {
  res.status(200).json({
    status: 'success',
    data: 'Successfully accessed the protected route.',
  });
};
