const router = require('express').Router();
const authController = require('../controllers/authController');

router.post('/signup', authController.signUp);
router.post('/login', authController.login);
router.post('/forgotPassword', authController.forgotPassword);
router.post('/resetPassword/:token', authController.resetPassword);

module.exports = router;
