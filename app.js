require('dotenv').config();
const express = require('express');
const userRoutes = require('./routes/userRoutes');
const sampleProtectedRoute = require('./routes/sampleProtectedRoute');
const expressErrorMiddleware = require('./middlewares/errorMiddleware');

const app = express();

app.use(express.json());
app.use('/user', userRoutes);
app.use('/sample-route', sampleProtectedRoute);
app.use(expressErrorMiddleware);

module.exports = app;
