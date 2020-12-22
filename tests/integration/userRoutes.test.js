const request = require('supertest');
const crypto = require('crypto');
const app = require('../../app');
const { User } = require('../../models/userModel');

describe('user routes', () => {
  let server;
  beforeEach(() => {
    server = app.listen(process.env.PORT || 3030);
  });
  afterEach(async () => {
    server.close();
    await User.deleteMany();
  });

  describe('/signup', () => {
    let username;
    let email;
    let password;
    let confirmPassword;

    beforeEach(() => {
      username = 'test1';
      email = 'test1@test.com';
      password = '12345Ab!';
      confirmPassword = '12345Ab!';
    });

    const happyPath = () => {
      return request(server)
        .post('/user/signup')
        .send({ username, email, password, confirmPassword });
    };

    it('should sign up a new user and return its data and a jwt token', async () => {
      const res = await happyPath();

      expect(res.status).toBe(201);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'success');
      expect(res.headers['set-cookie']).toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
      expect(res.body).toHaveProperty('data');
      expect(res.body.data).toHaveProperty('user');
      expect(res.body.data.user).toHaveProperty('username', 'test1');
      expect(res.body.data.user).toHaveProperty('email', 'test1@test.com');
    });

    it('should throw an error if no username provided', async () => {
      username = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Username is required.');
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw an error if no email provided', async () => {
      email = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Email is required.');
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw an error if email is invalid', async () => {
      email = 'test1@';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Invalid email.');
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw an error if no password entered', async () => {
      password = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Password is required.');
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw an error if confirm password field is empty', async () => {
      confirmPassword = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Enter your password again.');
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw an error if password does not meet the requirements', async () => {
      password = '12345Ab';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain(
        'Password should have at least eight characters containing at least one uppercase letter, one lowercase letter, one number, and one symbol.'
      );
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw an error if password and confirmPassword do not match', async () => {
      confirmPassword = '12345Ab!X';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Passwords do not match.');
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw an error if username is not unique', async () => {
      await User.create({
        username,
        email,
        password,
        confirmPassword,
      });
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain(
        'An account with this username already exists.'
      );
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw an error if email is not unique', async () => {
      await User.create({
        username: 'test2',
        email,
        password,
        confirmPassword,
      });
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain(
        'An account with this email already exists.'
      );
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });
  });

  describe('/login', () => {
    let username;
    let email;
    let password;
    let confirmPassword;
    beforeEach(async () => {
      username = 'test1';
      email = 'test1@test.com';
      password = 'Aa@12345';
      confirmPassword = 'Aa@12345';
      await User.create({
        username,
        email,
        password,
        confirmPassword,
      });
    });

    const happyPath = () => {
      return request(server).post('/user/login').send({
        username,
        password,
      });
    };

    it('should log the user in successfully if username and password are correct', async () => {
      const res = await happyPath();

      expect(res.status).toBe(200);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'success');
      expect(res.headers['set-cookie']).toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw 400 error if no username', async () => {
      username = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty(
        'message',
        'Please enter email and password.'
      );
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw 400 error if no password', async () => {
      password = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty(
        'message',
        'Please enter email and password.'
      );
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw 401 error if username is invalid', async () => {
      username = '123';
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty(
        'message',
        'Invalid username or password.'
      );
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });

    it('should throw 401 error if password is invalid', async () => {
      password = '123';
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty(
        'message',
        'Invalid username or password.'
      );
      expect(res.headers['set-cookie']).not.toEqual([
        expect.stringMatching(/^jwt=/),
      ]);
    });
  });

  describe('/forgotPassword', () => {
    let email;
    beforeEach(async () => {
      email = 'test1@test.com';
      await User.create({
        username: 'test1',
        email,
        password: 'Aa@12345',
        confirmPassword: 'Aa@12345',
      });
    });

    const happyPath = () => {
      return request(server).post('/user/forgotPassword').send({ email });
    };

    it('should send a password reset email successfully', async () => {
      const res = await happyPath();

      expect(res.status).toBe(200);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'success');
      expect(res.body).toHaveProperty(
        'message',
        'A link with instructions to reset your password has been sent to your email address.'
      );
    });

    it('should throw 400 error if no email', async () => {
      email = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Please enter your email.');
    });

    it('should throw 404 if user with the provided email not found', async () => {
      email = '123';
      const res = await happyPath();

      expect(res.status).toBe(404);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty(
        'message',
        'No user found with the provided email.'
      );
    });

    it('should throw 500 if could not send email', async () => {
      process.env.EMAIL_HOST = '';
      const res = await happyPath();
      const user = User.findOne({ email });

      expect(res.status).toBe(500);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty(
        'message',
        'There was an error sending the email. Try again later'
      );
      expect(user.passwordResetToken).toBe(undefined);
      expect(user.passwordResetExpired).toBe(undefined);
      process.env.EMAIL_HOST = 'smtp.mailtrap.io';
    });
  });

  describe('/resetPassword', () => {
    let token;
    let username;
    let password;
    let confirmPassword;
    let passwordResetExpired;
    beforeEach(async () => {
      token = 'abc';
      username = 'test1';
      password = 'Aa@12345';
      confirmPassword = 'Aa@12345';
      passwordResetExpired = Date.now() + 15 * 1000 * 60;
      const hashedToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
      await User.create({
        username,
        email: 'test1@test.com',
        password,
        confirmPassword,
        passwordResetToken: hashedToken,
        passwordResetExpired,
      });
    });

    const happyPath = () => {
      return request(server).post(`/user/resetPassword/${token}`).send({
        password,
        confirmPassword,
      });
    };

    it('should successfully reset the password of the user', async () => {
      const res = await happyPath();
      const user = await User.findOne({ username });

      expect(res.status).toBe(200);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'success');
      expect(res.body).toHaveProperty(
        'message',
        'Password updated successfully. You can login with your new credentials.'
      );
      expect(user).toHaveProperty('password');
      expect(user.passwordResetToken).toBe(undefined);
      expect(user.passwordResetExpired).toBe(undefined);
    });

    it('should throw 400 if token is invalid', async () => {
      token = 'a';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Invalid token.');
    });

    it('should throw 400 if token is expired', async () => {
      passwordResetExpired = Date.now() - 10000;
      await User.findOneAndUpdate(
        { username },
        { $set: { passwordResetExpired } }
      );
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Invalid token.');
    });
  });
});
