const mongoose = require('mongoose');
const app = require('./app');

mongoose
  .connect(process.env.DB_URI, {
    useCreateIndex: true,
    useFindAndModify: false,
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('connected to db.'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`listening on port ${port}`));
