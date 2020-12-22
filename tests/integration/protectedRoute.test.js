const request = require('supertest');
const app = require('../../app');
const { User } = require('../../models/userModel');

const prepareCookies = (res) => {
  const re = new RegExp('; path=/; httponly', 'gi');
  return res.headers['set-cookie']
    .map(function (cookie) {
      return cookie.replace(re, '');
    })
    .join('; ');
};

describe('Sample protected route', () => {
  describe('/sample-route', () => {
    let server;
    let cookies;
    beforeEach(async () => {
      server = app.listen(process.env.PORT || 3030);
      const res = await request(server).post('/user/signup').send({
        username: 'test2',
        email: 'test2@test.com',
        password: '12345Ab!',
        confirmPassword: '12345Ab!',
      });
      cookies = prepareCookies(res);
    });
    afterEach(async () => {
      server.close();
      await User.deleteMany();
    });

    const happyPath = () => {
      return request(server).get('/sample-route').set('Cookie', cookies);
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

    it('should throw 401 if no jwt cookie', async () => {
      cookies = '';
      const res = await happyPath();

      expect(res.status).toBe(401);
      expect(res.header['content-type']).toMatch(/json/);
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('message', 'You are not logged in.');
    });

    it('should throw 401 if jwt token is invalid', async () => {
      cookies = 'jwt=123554;';
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
