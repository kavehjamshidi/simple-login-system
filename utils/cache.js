const redis = require('redis');
const { promisify } = require('util');

const redisClient = redis.createClient(process.env.REDIS_URI);

redisClient.set = promisify(redisClient.set);
redisClient.get = promisify(redisClient.get);
redisClient.hset = promisify(redisClient.hset);
redisClient.hget = promisify(redisClient.hget);
redisClient.expire = promisify(redisClient.expire);
redisClient.del = promisify(redisClient.del);
redisClient.ttl = promisify(redisClient.ttl);

module.exports = redisClient;
