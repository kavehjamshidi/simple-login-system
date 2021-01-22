const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../../app');
const { User } = require('../../models/userModel');
const redisClient = require('../../utils/cache');

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
      expect(res.body).toHaveProperty('data');
      expect(res.body.data).toHaveProperty('user');
      expect(res.body.data.user).toHaveProperty('username', 'test1');
      expect(res.body.data.user).toHaveProperty('email', 'test1@test.com');
      expect(res.body.data).toHaveProperty('accessToken');
      expect(res.body.data).toHaveProperty('refreshToken');
    });

    it('should throw an error if no username provided', async () => {
      username = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Username is required.');
      expect(res.body).not.toHaveProperty('data');
    });

    it('should throw an error if no email provided', async () => {
      email = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Email is required.');
      expect(res.body).not.toHaveProperty('data');
    });

    it('should throw an error if email is invalid', async () => {
      email = 'test1@';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Invalid email.');
      expect(res.body).not.toHaveProperty('data');
    });

    it('should throw an error if no password entered', async () => {
      password = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Password is required.');
      expect(res.body).not.toHaveProperty('data');
    });

    it('should throw an error if confirm password field is empty', async () => {
      confirmPassword = '';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Enter your password again.');
      expect(res.body).not.toHaveProperty('data');
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
      expect(res.body).not.toHaveProperty('data');
    });

    it('should throw an error if password and confirmPassword do not match', async () => {
      confirmPassword = '12345Ab!X';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('Passwords do not match.');
      expect(res.body).not.toHaveProperty('data');
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
      expect(res.body).not.toHaveProperty('data');
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
      expect(res.body).not.toHaveProperty('data');
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
      expect(res.body.data).toHaveProperty('accessToken');
      expect(res.body.data).toHaveProperty('refreshToken');
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
      expect(res.body).not.toHaveProperty('data');
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
      expect(res.body).not.toHaveProperty('data');
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
      expect(res.body).not.toHaveProperty('data');
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
      expect(res.body).not.toHaveProperty('data');
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

    it('should throw 40 if email is invalid', async () => {
      email = '123';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Invalid email.');
    });
    it('should throw 404 if user with the provided email not found', async () => {
      email = '123@test.com';
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
      const temp = process.env.EMAIL_HOST;
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
      process.env.EMAIL_HOST = temp;
    });
  });

  describe('/resetPassword', () => {
    let token;
    let username;
    let password;
    let confirmPassword;
    beforeEach(async () => {
      token = 'abc';
      username = 'test1';
      password = 'Aa@12345';
      confirmPassword = 'Aa@12345';

      await redisClient.set(token, 'test1@test.com');
      await redisClient.expire(token, 900);
      await User.create({
        username,
        email: 'test1@test.com',
        password,
        confirmPassword,
      });
    });

    afterEach(async () => {
      await redisClient.del(token);
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
    });

    it('should throw 400 if token is invalid', async () => {
      token = 'a';
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Invalid reset token.');
    });

    it('should throw 400 if token is expired', async () => {
      await redisClient.del(token);
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Invalid reset token.');
    });

    it('should throw 400 if no user found', async () => {
      await User.deleteMany();
      const res = await happyPath();

      expect(res.status).toBe(400);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Invalid reset token.');
    });
  });

  describe('/refresh', () => {
    let refreshToken;
    let payload;
    beforeEach(async () => {
      const res = await request(server).post('/user/signup').send({
        username: 'test2',
        email: 'test2@test.com',
        password: '12345Ab!',
        confirmPassword: '12345Ab!',
      });
      ({ refreshToken } = res.body.data);
      payload = jwt.decode(refreshToken, process.env.JWT_SECRET);
    });

    afterEach(async () => {
      await redisClient.del(payload.jti);
    });

    const happyPath = () => {
      return request(server)
        .post('/user/refresh')
        .set('Authorization', `Bearer ${refreshToken}`);
    };

    it('should receive new refresh and access tokens', async () => {
      const res = await happyPath();

      expect(res.status).toBe(200);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'success');
      expect(res.body.data).toHaveProperty('accessToken');
      expect(res.body.data).toHaveProperty('refreshToken');

      expect(await redisClient.get(payload.jti)).toBe(payload.id);
      expect(await redisClient.ttl(payload.jti)).toBeLessThanOrEqual(
        payload.exp - parseInt(Date.now() / 1000, 10)
      );
    });

    it('should return 401 if no refresh token', async () => {
      refreshToken = '';
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'You are not logged in.');
      expect(res.body).not.toHaveProperty('data');
    });

    it('should return 400 if refresh token is invalid', async () => {
      refreshToken = 'jwt1234';
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Invalid token.');
      expect(res.body).not.toHaveProperty('data');
    });

    it('should return 401 if no user found', async () => {
      await User.deleteMany();
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'User not found.');
      expect(res.body).not.toHaveProperty('data');
    });

    it('should return 401 if login credentials have changed', async () => {
      await User.findOneAndUpdate(
        { username: 'test2' },
        { $set: { passwordChangeDate: Date.now() + 10000 } }
      );
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty(
        'message',
        'Login credentials have changed. Please login again.'
      );
      expect(res.body).not.toHaveProperty('data');
    });

    it('should return 403 if user in blacklist', async () => {
      await redisClient.set(payload.jti, payload.id);
      const res = await happyPath();
      await redisClient.del(payload.jti);

      expect(res.status).toBe(403);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Access forbidden.');
      expect(res.body).not.toHaveProperty('data');
    });
  });
});
