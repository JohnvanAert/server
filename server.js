const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const compression = require('compression');
const app = express();
const PORT = 5001;
require('dotenv').config();

// Настройки для базы данных
const dbUser = process.env.DB_USER;
const db = process.env.DB;
const host = process.env.HOST;
const dbPort = process.env.DB_PORT;
const dbPassword = process.env.DB_PASSWORD;

// Настройка пула подключений к PostgreSQL
const pool = new Pool({
  user: dbUser,
  host: host,
  database: db,
  password: dbPassword,
  port: dbPort,
});

// Middleware для работы с CORS, JSON и сжатие данных
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));
app.use(express.json());
app.use(compression());

// Middleware для работы с сессиями
app.use(session({
  store: new PgSession({
    pool: pool,            // Используем тот же пул для PostgreSQL
    tableName: 'user_sessions', // Таблица, где будут храниться сессии
  }),
  secret: process.env.SESSION_SECRET, // Секрет для подписи сессий
  resave: false,          // Не сохранять сессию, если она не изменялась
  saveUninitialized: false, // Не сохранять сессии, которые не были инициализированы
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // Время жизни куки (1 день)
    secure: process.env.NODE_ENV === 'production', // secure=true только в продакшене
    httpOnly: true, // Только HTTP, чтобы защититься от XSS атак
  }
}));

// Middleware для проверки авторизации через сессии
const authenticateSession = (req, res, next) => {
  if (req.session.user) {
    console.log("Session authenticated for user:", req.session.user);
    next();
  } else {
    console.log("Unauthorized access attempt");
    res.status(401).json({ message: 'Not authorized' });
  }
};

// Маршрут для логина (аутентификация)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  console.log("Login request received for:", username); // Логируем запрос

  try {
    // Поиск пользователя в базе данных
    const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (userResult.rows.length === 0) {
      console.log("User not found:", username);
      return res.status(400).json({ message: 'User not found' });
    }

    const user = userResult.rows[0];
    console.log("User found:", user.username); // Логируем найденного пользователя

    // Проверка пароля
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      console.log("Invalid password for user:", username);
      return res.status(400).json({ message: 'Invalid password' });
    }

    console.log("Password validated for user:", username); // Логируем успешную проверку пароля

    // Сохраняем данные пользователя в сессии
    req.session.user = { id: user.id, role: user.role, email: user.email, team_id: user.team_id };
    
    res.json({ message: 'Login successful' });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Маршрут для получения данных пользователя
app.get('/api/user', authenticateSession, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.user.id]);

    if (userResult.rows.length === 0) {
      console.log("User not found for session user ID:", req.session.user.id);
      return res.status(404).json({ message: 'User not found' });
    }

    const user = userResult.rows[0];
    res.json({ id: user.id, username: user.username, role: user.role, email: user.email });
  } catch (err) {
    console.error("Error fetching user data:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Маршрут для проверки сессии
app.get('/api/check-session', (req, res) => {
  if (req.session.user) {
    console.log('Active session:', req.session);  // Логируем сессию на сервере
    res.json({ isAuthenticated: true, user: req.session.user });
  } else {
    res.json({ isAuthenticated: false });
  }
});


// Маршрут для Team Leader
app.get('/api/teamleader', authenticateSession, (req, res) => {
  if (req.session.user.role !== 'teamleader') {
    return res.status(403).json({ message: 'Access denied' });
  }

  res.json({ message: 'Welcome, Team Leader!' });
});

// Маршрут для Admin
app.get('/api/admin', authenticateSession, (req, res) => {
  if (req.session.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied' });
  }

  res.json({ message: 'Welcome, Admin!' });
});

// Маршрут для выхода из системы (logout)
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error("Error during logout:", err);
      return res.status(500).json({ message: 'Logout failed' });
    }
    res.clearCookie('connect.sid'); // Очищаем куки
    res.json({ message: 'Logout successful' });
  });
});

// Маршрут для обновления сессии
app.post('/api/refresh-session', authenticateSession, (req, res) => {
  req.session.touch();  // Обновляет срок действия сессии
  res.json({ message: 'Session refreshed' });
});

// Маршрут для проверки сессии
app.get('/api/check-session', (req, res) => {
  if (req.session.user) {
    console.log("Session active for user:", req.session.user.username); // Логируем активную сессию
    res.json({ isAuthenticated: true, user: req.session.user });
  } else {
    console.log("No active session");
    res.json({ isAuthenticated: false });
  }
});

// Middleware для обработки ошибок
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.stack);
  res.status(500).json({ message: 'Internal Server Error' });
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
