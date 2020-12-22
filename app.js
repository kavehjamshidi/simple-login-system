require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');

const logger = require('./utils/logger');
const userRoutes = require('./routes/userRoutes');
const sampleProtectedRoute = require('./routes/sampleProtectedRoute');
const notFoundController = require('./controllers/notFoundController');
const expressErrorMiddleware = require('./middlewares/errorMiddleware');

// Unhandled promise rejections and uncaught exceptions
require('./utils/unhandledErrors')();

mongoose
  .connect(process.env.DB_URI, {
    useCreateIndex: true,
    useFindAndModify: false,
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => logger.info('connected to db.'));

const app = express();

// Security Headers
app.use(helmet());

// Body Parser / Cookie Parser
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// NoSQL query injection
app.use(mongoSanitize());

// XSS protection
app.use(xss());

app.use('/user', userRoutes);
app.use('/sample-route', sampleProtectedRoute);
app.all('*', notFoundController);
app.use(expressErrorMiddleware);

module.exports = app;
