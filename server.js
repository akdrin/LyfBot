const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 4000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));


const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '9956',
  database: 'lyf_db',
});

db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
    process.exit(1);
  }
  console.log('Connected to MySQL database');
});

const createUsersTableQuery = `
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
  )
`;

db.query(createUsersTableQuery, (err) => {
  if (err) {
    console.error('Error creating users table:', err);
    process.exit(1);
  }
  console.log('Users table is ready');
});

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    db.query(query, [username, email, hashedPassword], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'Username or email already exists' });
        }
        console.error('Database error during signup:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }
      res.redirect('/login.html');
    });
  } catch (error) {
    console.error('Error during signup:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error('Database error during login:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    res.redirect('/welcome.html'); 
  });
});

app.use((req, res) => {
  res.status(404).send('<h1>404: Page Not Found</h1>');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
