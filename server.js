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
    // Проверка пароля
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      
      return res.status(400).json({ message: 'Invalid password' });
    }

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

// Универсальный маршрут для получения данных команд
app.get('/teams', async (req, res, next) => {
  // Проверка, что пользователь авторизован
  if (!req.session.user) {
    return res.redirect('/unauthorized'); // Перенаправляем на маршрут /unauthorized
  }

  const { id: userId, role, team_id } = req.session.user;

  try {
    let query;
    let queryParams = [];

    // Логика для администратора
    if (role === 'admin') {
      query = `
        SELECT users.id, users.username AS name, users.role, teams.name AS team_name
        FROM users
        JOIN teams ON users.team_id = teams.id
        ORDER BY teams.name, 
                 CASE WHEN users.role = 'team_leader' THEN 0 ELSE 1 END, 
                 users.id;
      `;
    }
    // Логика для тимлидера
    else if (role === 'team_leader') {
      query = `
        SELECT users.id, users.username, users.role, teams.name 
        FROM users
        JOIN teams ON users.team_id = teams.id
        WHERE teams.leader_id = $1
        ORDER BY users.role = 'team_leader' DESC, users.id ASC;
      `;
      queryParams = [userId];
    }
    // Логика для обычного пользователя
    else if (role === 'user') {
      query = `
        SELECT users.id, users.username, users.role
        FROM users
        WHERE users.team_id = $1
        ORDER BY users.role = 'team_leader' DESC, users.id ASC;
      `;
      queryParams = [team_id];
    } else {
      return res.redirect('/unauthorized');
    }

    // Выполняем запрос
    const result = await pool.query(query, queryParams);
    res.json(result.rows);

  } catch (error) {
    console.error('Error fetching team data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



// конец получения таблицы


//Tickets

// Маршрут для добавления нового тикета для тимлидера
app.post('/api/tickets', async (req, res) => {
  const { amount, description, link } = req.body;
  
  if (!req.session.user || req.session.user.role !== 'user') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO tickets (user_id, amount, description, link) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.session.user.id, amount, description, link]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error adding ticket:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Маршрут для создания тикета
app.post('/requests/add', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'user') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { amount, link, quantity } = req.body;
  const userId = req.session.user.id;

  try {
    const result = await pool.query(`
      INSERT INTO requests(user_id, amount, link, quantity, status, created_at, updated_at)
      VALUES ($1, $2, $3, $4, 'pending', NOW(), NOW())
      RETURNING *;
    `, [userId, amount, link, quantity]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error on adding new request:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/teamleader/requests', async (req, res) => {
  const teamId = req.session.user.team_id;

  if (!teamId) {
    return res.status(400).json({ error: 'Team ID не установлен в сессии' });
  }

  try {
    const requests = await pool.query(
      `SELECT r.id, r.user_id, r.amount, r.link, r.quantity, r.status, r.created_at
       FROM requests r
       JOIN users u ON u.id = r.user_id
       WHERE u.team_id = $1
       AND r.status = 'pending'`,
      [teamId]
    );

    res.json(requests.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Ошибка при получении заявок');
  }
});


//End of tickets


//TeamLead Reject Function


// Маршрут для утверждения заявки тимлидером
app.put('/teamleader/requests/approve/:requestId', async (req, res) => {
  const requestId = req.params.requestId;
  const teamId = req.session.user.team_id;

  if (req.session.user.role !== 'team_leader') {
    return res.status(403).json({ message: 'Access denied' });
  }

  try {
    // Обновляем статус заявки на "approved"
    const result = await pool.query(`
      UPDATE requests
      SET status = 'approved', updated_at = NOW()
      WHERE id = $1 AND user_id IN (SELECT id FROM users WHERE team_id = $2)
      RETURNING *;
    `, [requestId, teamId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Request not found or does not belong to your team' });
    }

    res.json({ message: 'Request approved', request: result.rows[0] });
  } catch (err) {
    console.error('Error approving request:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Маршрут для отклонения заявки тимлидером
app.put('/teamleader/requests/reject/:requestId', async (req, res) => {
  const requestId = req.params.requestId;
  const teamId = req.session.user.team_id;

  if (req.session.user.role !== 'team_leader') {
    return res.status(403).json({ message: 'Access denied' });
  }

  try {
    // Обновляем статус заявки на "rejected"
    const result = await pool.query(`
      UPDATE requests
      SET status = 'rejected', updated_at = NOW()
      WHERE id = $1 AND user_id IN (SELECT id FROM users WHERE team_id = $2)
      RETURNING *;
    `, [requestId, teamId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Request not found or does not belong to your team' });
    }

    res.json({ message: 'Request rejected', request: result.rows[0] });
  } catch (err) {
    console.error('Error rejecting request:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});




//End of teamlead finction



// Маршрут для проверки сессии
app.get('/api/check-session', (req, res) => {
  if (req.session.user) {
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
