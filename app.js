require('dotenv').config();
const express = require('express');
const userRoutes = require('./routes/userRoutes');
const sampleProtectedRoute = require('./routes/sampleProtectedRoute');
const notFoundController = require('./controllers/notFoundController');
const expressErrorMiddleware = require('./middlewares/errorMiddleware');

// Unhandled promise rejections and uncaught exceptions
require('./utils/unhandledErrors')();

const app = express();

app.use(express.json());
app.use('/user', userRoutes);
app.use('/sample-route', sampleProtectedRoute);
app.all('*', notFoundController);
app.use(expressErrorMiddleware);

module.exports = app;
