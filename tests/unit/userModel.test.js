const bcrypt = require('bcrypt');
const {
  User,
  hashPassword,
  createValidationError,
  passwordRegExTest,
  validateConfirmPassword,
} = require('../../models/userModel');
const AppError = require('../../utils/appError');

describe('createValidationError hook', () => {
  let next;

  beforeEach(() => {
    next = jest.fn();
  });

  it('should create an app error and call next with it if there is an error', () => {
    const err = new Error('A fake error');

    createValidationError(err, undefined, next);

    expect(next).toBeCalledTimes(1);
    expect(next).toBeCalledWith(expect.any(AppError));
    expect(next).toBeCalledWith(
      expect.objectContaining({ message: 'A fake error', statusCode: 400 })
    );
  });

  it('should call next with no arguments if there is no error', () => {
    createValidationError(undefined, undefined, next);

    expect(next).toBeCalledTimes(1);
    // assert "next" was called with zero arguments
    expect(next.mock.calls[0].length).toBe(0);
  });
});

describe('hashPassword', () => {
  let next;
  let thisArg;
  beforeEach(() => {
    next = jest.fn();
    thisArg = {
      isModified: jest.fn(),
      password: '123456',
      confirmPassword: '123456',
    };
  });

  it('should hash password if password is modified', async () => {
    thisArg.isModified.mockReturnValueOnce(true);
    await hashPassword.call(thisArg, next);

    expect(next).toBeCalledTimes(1);
    expect(thisArg.isModified).toBeCalledWith('password');
    expect(thisArg.password).not.toBe('123456');
    expect(thisArg.confirmPassword).toBe(undefined);
    expect(thisArg).toHaveProperty('passwordChangeDate');
  });

  it('should call next if password not modified', async () => {
    thisArg.isModified.mockReturnValueOnce(false);
    await hashPassword.call(thisArg, next);

    expect(thisArg.isModified).toBeCalledWith('password');
    expect(next).toBeCalledTimes(1);
    expect(thisArg.password).toBe('123456');
  });
});

describe('passwordRegExTest', () => {
  it('should return false because password is shorter than eight characters', () => {
    const password = '!Ab12';
    const result = passwordRegExTest(password);

    expect(result).toBe(false);
  });

  it('should return false because password contains no numbers', () => {
    const password = '!Akkkkfsbw[';
    const result = passwordRegExTest(password);

    expect(result).toBe(false);
  });

  it('should return false because password contains no lowercase letters', () => {
    const password = 'AABN1235LL?';
    const result = passwordRegExTest(password);

    expect(result).toBe(false);
  });

  it('should return false because password contains no uppercase letters', () => {
    const password = 'anmfb1235e?';
    const result = passwordRegExTest(password);

    expect(result).toBe(false);
  });

  it('should return false because password contains no special characters', () => {
    const password = 'G231fd8e2s';
    const result = passwordRegExTest(password);

    expect(result).toBe(false);
  });

  it('should return true', () => {
    const password = '/F1235mk?f';
    const result = passwordRegExTest(password);

    expect(result).toBe(true);
  });
});

describe('validateConfirmPassword', () => {
  let thisArg;
  beforeEach(() => {
    thisArg = {
      password: '123456',
    };
  });

  it('should return false if password and confirm password fields do not match', () => {
    const result = validateConfirmPassword.call(thisArg, '12345');

    expect(result).toBe(false);
  });

  it('should return true if password and confirm password fields match', () => {
    const result = validateConfirmPassword.call(thisArg, '123456');

    expect(result).toBe(true);
  });
});

describe('comparePassword method', () => {
  it('should return false if the password and the hashed password does not match', async () => {
    const hashedPassword = await bcrypt.hash('123456', 12);
    const user = new User({ password: hashedPassword });
    const result = await user.comparePassword('12345');

    expect(result).toBe(false);
  });

  it('should return true if the password and the hashed password match', async () => {
    const hashedPassword = await bcrypt.hash('123456', 12);
    const user = new User({ password: hashedPassword });
    const result = await user.comparePassword('123456');

    expect(result).toBe(true);
  });
});

describe('changedPasswordAfterToken method', () => {
  it('should return true if password was changed after the token had been issued', () => {
    const user = new User({ passwordChangeDate: new Date() });
    const tokenIssuedTimestamp = user.passwordChangeDate.getTime() / 1000 - 10;
    const result = user.changedPasswordAfterToken(tokenIssuedTimestamp);

    expect(result).toBe(true);
  });

  it('should return false if password was not changed after the token had been issued', () => {
    const user = new User({ passwordChangeDate: new Date() });
    const tokenIssuedTimestamp = user.passwordChangeDate.getTime() / 1000 + 10;
    const result = user.changedPasswordAfterToken(tokenIssuedTimestamp);

    expect(result).toBe(false);
  });
});

describe('createPasswordResetToken', () => {
  it('should create password reset token and its expiry date', () => {
    const user = new User();
    const resetToken = user.createPasswordResetToken();

    expect(resetToken).toBeTruthy();
    expect(user).toHaveProperty('passwordResetToken');
    expect(user).toHaveProperty('passwordResetExpired');
    expect(user.passwordResetExpired.getTime()).toBeLessThanOrEqual(
      Date.now() + 15 * 60 * 1000
    );
  });
});
