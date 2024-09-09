const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const app = express();
const PORT = 5001;
require('dotenv').config();

// Секретный ключ для подписи JWT
const JWT_SECRET = process.env.JWT_SECRET;
const dbUser = process.env.DB_USER;
const db = process.env.DB;
const host = process.env.HOST
const port = process.env.PORT
const dbPassword = process.env.DB_PASSWORD;
// Настройка пула подключений к PostgreSQL
const pool = new Pool({
  user: dbUser,        // Ваше имя пользователя PostgreSQL
  host: host,            // Адрес сервера базы данных (или URL)
  database: db,    // Имя базы данных
  password: dbPassword,    // Пароль от PostgreSQL
  port: port,                   // Порт PostgreSQL (по умолчанию 5432)
});

// Middleware для работы с CORS и JSON
app.use(cors({
  origin: 'http://localhost:3000',  // URL вашего клиента
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,  // Важно, если используется авторизация
}));
app.use(express.json());

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Извлечение токена без "Bearer"
  
  if (!token) return res.status(403).json({ message: 'Token is required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};


// Маршрут для логина (аутентификация)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Поиск пользователя в базе данных
    const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }

    const user = userResult.rows[0];

    // Проверка пароля
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    // Создание JWT токена
    const token = jwt.sign({ id: user.id, role: user.role, email: user.email, team_id: user.team_id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Защищенный маршрут для получения данных пользователя
app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = userResult.rows[0];
    res.json({ id: user.id, username: user.username, role: user.role, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Маршрут для Team Leader
app.get('/api/teamleader', authenticateToken, (req, res) => {
  if (req.user.role !== 'teamleader') {
    return res.status(403).json({ message: 'Access denied' });
  }

  res.json({ message: 'Welcome, Team Leader!' });
});

// Маршрут для Admin
app.get('/api/admin', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied' });
  }

  res.json({ message: 'Welcome, Admin!' });
});

// Маршрут для валидации токена
app.get('/api/validate-token', authenticateToken, (req, res) => {
  res.json({ message: 'Token is valid', user: req.user });
});


// Запуск сервера
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
