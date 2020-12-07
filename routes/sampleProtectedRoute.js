const router = require('express').Router();
const sampleRouteController = require('../controllers/sampleRouteController');
const authController = require('../controllers/authController');

router.get('/', authController.protect, sampleRouteController);

module.exports = router;
