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
    res.status(401).json({ message: 'Not authorized' });
  }
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
    console.log("User found:", user.username); // Логируем найденного пользователя

    // Проверка пароля
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      
      return res.status(400).json({ message: 'Invalid password' });
    }

    console.log("Password validated for user:", username); // Логируем успешную проверку пароля

    // Сохраняем данные пользователя в сессии
    req.session.user = { id: user.id, role: user.role, email: user.email, team_id: user.team_id };
    
    res.json({ message: 'Login successful' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});



// Маршрут для получения данных пользователя
app.get('/api/user', authenticateSession, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.user.id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = userResult.rows[0];
    res.json({ id: user.id, username: user.username, role: user.role, email: user.email });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});


//Получить таблицы с коммандами

// Маршрут для получения данных о командах
app.get('/admin/teams', async (req, res) => {
  try {
    // SQL-запрос для получения данных о всех командах и их пользователях
    const teamsData = await pool.query(`
      SELECT users.id, users.username AS name, users.role, teams.name AS team_name
      FROM users
      JOIN teams ON users.team_id = teams.id
      ORDER BY teams.name, 
               CASE WHEN users.role = 'team_leader' THEN 0 ELSE 1 END, 
               users.id;
    `);
    
    // Возвращаем данные в формате JSON
    res.json(teamsData.rows);
  } catch (err) {
    console.error('Error fetching teams data:', err);
    res.status(500).json({ error: 'Server error fetching teams data' });
  }
});


// Маршрут для проверки сессии
app.get('/api/check-session', (req, res) => {
  if (req.session.user) {
    res.json({ isAuthenticated: true, user: req.session.user });
  } else {
    res.json({ isAuthenticated: false });
  }
});


// Маршрут для получения данных команды тимлидера
app.get('/teamleader/team', (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'team_leader') {
    // Возвращаем 403 если пользователь не team_leader или сессия не установлена
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
}, async (req, res) => {
  const { id: userId } = req.session.user;
  try {
    const result = await pool.query(`
      SELECT users.id, users.username, users.role, teams.name 
      FROM users
      JOIN teams ON users.team_id = teams.id
      WHERE teams.leader_id = $1
      ORDER BY users.role = 'team_leader' DESC, users.id ASC;
    `, [userId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error on fetching team data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/user/team', (req, res, next) => {
  // Проверка, что пользователь существует и у него роль не 'user'
  if (!req.session.user || req.session.user.role !== 'user') {
    return res.redirect('/unauthorized'); // Перенаправляем на маршрут /unauthorized
  }
  next();
}, async (req, res) => {
  const { team_id } = req.session.user;
  try {
    const result = await pool.query(`
      SELECT users.id, users.username, users.role
      FROM users
      WHERE users.team_id = $1
      ORDER BY users.role = 'team_leader' DESC, users.id ASC;
    `, [team_id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error on fetching team data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// конец получения таблицы


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
    res.json({ isAuthenticated: true, user: req.session.user });
  } else {
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
