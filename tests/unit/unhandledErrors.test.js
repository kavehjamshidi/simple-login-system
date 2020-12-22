const unhandledErrors = require('../../utils/unhandledErrors');
const logger = require('../../utils/logger');

describe('unhandledErrors', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should handle uncaughtException', () => {
    const mError = new Error('fake uncaught exception');
    jest.spyOn(process, 'on').mockImplementation((event, handler) => {
      if (event === 'uncaughtException') {
        handler(mError);
      }
    });
    jest.spyOn(logger, 'error').mockReturnValueOnce();
    jest.spyOn(process, 'exit').mockReturnValueOnce();
    unhandledErrors();

    expect(process.on).toBeCalledWith(
      'uncaughtException',
      expect.any(Function)
    );
    expect(process.exit).toBeCalledWith(1);
    expect(logger.error).toBeCalledWith('fake uncaught exception', mError);
  });

  it('should handle unhandledRejection', () => {
    const mError = new Error('fake unhandled rejection');
    jest.spyOn(process, 'on').mockImplementation((event, handler) => {
      if (event === 'unhandledRejection') {
        handler(mError);
      }
    });
    expect(() => unhandledErrors()).toThrowError('fake unhandled rejection');
    expect(process.on).toBeCalledWith(
      'unhandledRejection',
      expect.any(Function)
    );
  });
});
