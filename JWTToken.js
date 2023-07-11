const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');


const app = express();
app.use(express.json());

const secretKey = process.env.JWT_SECRET || 'secret-key'; 

const users = [];

// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  const userExists = users.find(u => u.username === username);
  if (userExists) {
    return res.status(400).json({ error: 'Username already exists' });
  }
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = {
      id: users.length + 1,
      username: username,
      password: hashedPassword
    };
    users.push(newUser);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);


  if (user && bcrypt.compareSync(password, user.password)) {
    const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid username or password' });
  }
});

//Token Authentication
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'You have accessed a protected endpoint.' });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) {
      return res.status(401).json({ error: 'Missing token' });
    }
  
    console.log('Token:', token);
    try {
      jwt.verify(token, secretKey, (err, decodedToken) => {
        if (err) {
          console.error('Token Verification Error:', err);
          return res.status(403).json({ error: 'Invalid token' });
        }
  
        console.log('Decoded Token (jsonwebtoken):', decodedToken); // Log the decoded token for debugging
  
        req.userId = decodedToken.userId;
        next();
      });
    } catch (error) {
      console.error('Token Decoding Error:', error);
      return res.status(403).json({ error: 'Invalid token' });
    }
  }



app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});