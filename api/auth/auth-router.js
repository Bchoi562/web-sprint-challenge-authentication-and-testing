const router = require('express').Router();
const jwt = require('jsonwebtoken'); 
const bcryptjs = require('bcryptjs'); 

const jwtSecret = require('../../config/secret'); 
const UserAuth = require('./auth-model');
const { validateCreds, usernameAvailability } = require('../middleware/middleware');

//HELPERS
const createToken = (user) => {
  const payload = {
    id: user.id,
    username: user.username
  }; 
  const options = {
    expiresIn: '1h'
  };
  return jwt.sign(payload, jwtSecret, options);
};

//END POINTS
router.get('/', async (req, res) => {
  try {
    const users = await UserAuth.getAll();
    res.status(200).json(users); 
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.post('/register', validateCreds, usernameAvailability, async (req, res) => {
  const newUser = req.body; 
  const rounds = process.env.BCRYPT_ROUNDS || 4;
  
  const hash = bcryptjs.hashSync(newUser.password, rounds); 
  newUser.password = hash;

  try {
    const addedUser = await UserAuth.addUser(newUser);
    res.status(200).json(addedUser); 
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
 
});

router.post('/login',validateCreds, async (req, res) => {
  const { username, password } = req.body; 

  try { 
    const user = await UserAuth.findBy({ username: username});
    if (user && bcryptjs.compareSync(password, user.password)) {
      const token = createToken(user); 
      res.status(200).json({
        message: `welcome, ${user.username}`, 
        token: token
      });
    } else {
      res.status(401).json("invalid credentials"); 
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
 
});

module.exports = router;