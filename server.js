const mongoose = require('mongoose');
const app = require('./app');
const logger = require('./utils/logger');

mongoose
  .connect(process.env.DB_URI, {
    useCreateIndex: true,
    useFindAndModify: false,
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => logger.info('connected to db.'));

const port = process.env.PORT || 3000;
app.listen(port, () => logger.info(`listening on port ${port}`));
