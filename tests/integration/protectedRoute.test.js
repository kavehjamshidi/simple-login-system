const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../../app');
const { User } = require('../../models/userModel');
const redisClient = require('../../utils/cache');

describe('Sample protected route', () => {
  describe('/sample-route', () => {
    let server;
    let accessToken;
    beforeEach(async () => {
      server = app.listen(process.env.PORT || 3030);
      const res = await request(server).post('/user/signup').send({
        username: 'test2',
        email: 'test2@test.com',
        password: '12345Ab!',
        confirmPassword: '12345Ab!',
      });
      ({ accessToken } = res.body.data);
    });
    afterEach(async () => {
      server.close();
      await User.deleteMany();
    });

    const happyPath = () => {
      return request(server)
        .get('/sample-route')
        .set('Authorization', `Bearer ${accessToken}`);
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

    it('should throw 401 if no jwt token', async () => {
      accessToken = '';
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'You are not logged in.');
    });

    it('should throw 401 if jwt token is invalid', async () => {
      accessToken = 'jwt1234';
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Invalid token.');
    });

    it('should throw 401 if user no longer exists', async () => {
      await User.deleteMany();
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'User not found.');
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

    it('should throw 403 if user in blacklist', async () => {
      const payload = jwt.decode(accessToken);
      await redisClient.set(payload.jti, payload.id);
      const res = await happyPath();
      await redisClient.del(payload.jti);

      expect(res.status).toBe(403);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'Access forbidden.');
    });
  });
});
