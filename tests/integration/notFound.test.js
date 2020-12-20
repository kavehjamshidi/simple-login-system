const request = require('supertest');
const app = require('../../app');

describe('Not found route', () => {
  let server;
  beforeEach(() => {
    server = app.listen(process.env.PORT || 3030);
  });
  afterEach(() => server.close());

  it('should throw 404 error for GET request', async () => {
    const res = await request(server).get('/1');

    expect(res.status).toBe(404);
    expect(res.header['content-type']).toMatch(/json/);
    expect(res.body).toHaveProperty('status', 'error');
    expect(res.body).toHaveProperty(
      'message',
      'Could not find the requested URL.'
    );
  });

  it('should throw 404 error for POST request', async () => {
    const res = await request(server).post('/1');

    expect(res.status).toBe(404);
    expect(res.header['content-type']).toMatch(/json/);
    expect(res.body).toHaveProperty('status', 'error');
    expect(res.body).toHaveProperty(
      'message',
      'Could not find the requested URL.'
    );
  });

  it('should throw 404 error for DELETE request', async () => {
    const res = await request(server).post('/1');

    expect(res.status).toBe(404);
    expect(res.header['content-type']).toMatch(/json/);
    expect(res.body).toHaveProperty('status', 'error');
    expect(res.body).toHaveProperty(
      'message',
      'Could not find the requested URL.'
    );
  });

  it('should throw 404 error for PUT request', async () => {
    const res = await request(server).put('/1');

    expect(res.status).toBe(404);
    expect(res.header['content-type']).toMatch(/json/);
    expect(res.body).toHaveProperty('status', 'error');
    expect(res.body).toHaveProperty(
      'message',
      'Could not find the requested URL.'
    );
  });

  it('should throw 404 error for PATCH request', async () => {
    const res = await request(server).patch('/1');

    expect(res.status).toBe(404);
    expect(res.header['content-type']).toMatch(/json/);
    expect(res.body).toHaveProperty('status', 'error');
    expect(res.body).toHaveProperty(
      'message',
      'Could not find the requested URL.'
    );
  });
});
