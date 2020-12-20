const request = require('supertest');
const app = require('../../app');
const { User } = require('../../models/userModel');

describe('Sample protected route', () => {
  describe('/sample-route', () => {
    let server;
    let token;
    let authHeader;
    beforeEach(async () => {
      server = app.listen(process.env.PORT || 3030);
      const res = await request(server).post('/user/signup').send({
        username: 'test2',
        email: 'test2@test.com',
        password: '12345Ab!',
        confirmPassword: '12345Ab!',
      });
      ({ token } = res.body);
      authHeader = `Bearer ${token}`;
    });
    afterEach(async () => {
      server.close();
      await User.deleteMany();
    });

    const happyPath = () => {
      return request(server)
        .get('/sample-route')
        .set('authorization', authHeader);
    };

    it('should let user access the protected route', async () => {
      const res = await happyPath();

      expect(res.status).toBe(200);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'success');
      expect(res.body).toHaveProperty(
        'data',
        'Successfully accessed the protected route.'
      );
    });

    it('should throw 401 if no auth header', async () => {
      authHeader = '';
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'You are not logged in.');
    });

    it('should throw 401 if no token in auth header', async () => {
      authHeader = 'Bearer';
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'You are not logged in.');
    });

    it('should throw 401 if token is invalid', async () => {
      authHeader = 'Bearer 123';

      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty(
        'message',
        'Invalid token. Please login again.'
      );
    });

    it('should throw 401 if user no longer exists', async () => {
      await User.deleteMany();
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'The user no longer exists.');
    });

    it('should throw 401 if user credentials have changed after token had been issued', async () => {
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
    });
  });
});
