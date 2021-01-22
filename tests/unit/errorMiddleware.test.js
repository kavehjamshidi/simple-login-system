const errorMiddleware = require('../../middlewares/errorMiddleware');

describe('Error middleware', () => {
  let res;
  let next;
  let err;
  beforeEach(() => {
    res = {
      status: jest.fn().mockReturnValue({ json: jest.fn() }),
      json: jest.fn(),
    };
    next = jest.fn();
    err = new Error('fake error');
  });

  it('should return an error with default status 500', () => {
    errorMiddleware(err, {}, res, next);

    expect(res.status).toBeCalledTimes(1);
    expect(res.status).toBeCalledWith(500);
    expect(res.status(500).json).toBeCalledTimes(1);
    expect(res.status(500).json).toBeCalledWith(
      expect.objectContaining({
        status: 'error',
        message: 'Something went wrong.',
      })
    );
  });

  it('should return an error with status 403', () => {
    err.statusCode = 403;
    errorMiddleware(err, {}, res, next);

    expect(res.status).toBeCalledTimes(1);
    expect(res.status).toBeCalledWith(403);
    expect(res.status(403).json).toBeCalledTimes(1);
    expect(res.status(403).json).toBeCalledWith(
      expect.objectContaining({ status: 'error', message: 'fake error' })
    );
  });

  it('should handle jwt error', () => {
    err.name = 'JsonWebToken';
    errorMiddleware(err, {}, res, next);

    expect(res.status).toBeCalledTimes(1);
    expect(res.status).toBeCalledWith(401);
    expect(res.status(401).json).toBeCalledTimes(1);
    expect(res.status(401).json).toBeCalledWith(
      expect.objectContaining({
        status: 'error',
        message: 'Invalid token.',
      })
    );
  });

  it('should handle jwt token expired error', () => {
    err.name = 'TokenExpiredError';
    errorMiddleware(err, {}, res, next);

    expect(res.status).toBeCalledTimes(1);
    expect(res.status).toBeCalledWith(401);
    expect(res.status(401).json).toBeCalledTimes(1);
    expect(res.status(401).json).toBeCalledWith(
      expect.objectContaining({
        status: 'error',
        message: 'Your token has expired.',
      })
    );
  });

  it('should handle mongoose duplicity error', () => {
    err.code = 11000;
    err.keyPattern = { property: 1 };
    errorMiddleware(err, {}, res, next);

    expect(res.status).toBeCalledTimes(1);
    expect(res.status).toBeCalledWith(400);
    expect(res.status(400).json).toBeCalledTimes(1);
    expect(res.status(400).json).toBeCalledWith(
      expect.objectContaining({
        status: 'error',
        message: 'An account with this property already exists.',
      })
    );
  });
});
