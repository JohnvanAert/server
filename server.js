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
const multer = require('multer');
const path = require('path');

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
    req.session.user = { id: user.id, name: username, role: user.role, email: user.email, team_id: user.team_id };
    
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


app.put('/teamleader/requests/:id/approve', async (req, res) => {
  const requestId = req.params.id;

  try {
    // Step 1: Approve the request
    console.log("Request ID to approve:", requestId);
    const requestResult = await pool.query('UPDATE requests SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *', ['approved', requestId]);
    
    const approvedRequest = requestResult.rows[0];

    if (!approvedRequest) {
      return res.status(404).json({ message: 'Request not found' });
    }

    // Step 2: Insert into the expenses table
    console.log("Inserting into expenses:", {
      user_id: approvedRequest.user_id,
      request_id: approvedRequest.id,
      amount: approvedRequest.amount,
    });

    const insertExpense = await pool.query(
      'INSERT INTO expenses (user_id, request_id, amount, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *',
      [approvedRequest.user_id, approvedRequest.id, approvedRequest.amount]
    );


    // Step 3: Send response
    res.status(200).json({
      message: 'Request approved and moved to expenses',
      expense: insertExpense.rows[0],
    });

  } catch (error) {
    res.status(500).send("Server error");
  }
});




app.put('/teamleader/requests/:id/reject', async (req, res) => {
  const requestId = req.params.id;
  console.log("Request ID:", requestId);  // Логируем ID заявки
  console.log("Request body:", req.body);  // Логируем тело запроса

  try {
    const result = await pool.query('UPDATE requests SET status = $1 WHERE id = $2 RETURNING *', ['rejected', requestId]);
    res.status(200).json({ message: "Request rejected successfully" });
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});


//End of teamlead finction


//Expenses
app.get('/api/expenses', async (req, res) => {
  const userRole = req.session.user.role;
  const teamId = req.session.user.team_id;
  const limit = parseInt(req.query.limit) || 10;  
  const offset = parseInt(req.query.offset) || 0;  
  const sortBy = req.query.sortBy || 'created_at';
  const sortOrder = req.query.sortOrder === 'desc' ? 'DESC' : 'ASC';

  const webmasterFilter = req.query.webmaster || null;
  const amountFilter = req.query.amount || null;
  const startDate = req.query.startDate || null;
  const endDate = req.query.endDate || null;
  const teamFilter = req.query.team || null;

  const validSortFields = {
    'created_at': 'expenses.created_at',
    'amount': 'expenses.amount',
    'username': 'users.username',
    'team_name': 'teams.name',
  };

  const sortByField = validSortFields[sortBy] || 'expenses.created_at';

  try {
    let query = '';
    let params = [limit, offset];
    let countQuery = '';
    let countParams = [];

    let paramIndex = params.length + 1; // Начинаем с индекса, который будет следующим

    if (userRole === 'admin') {
      query = `
        SELECT expenses.*, requests.amount, requests.link, users.username, teams.name as team_name
        FROM expenses
        JOIN requests ON expenses.request_id = requests.id
        JOIN users ON expenses.user_id = users.id
        JOIN teams ON users.team_id = teams.id
        WHERE 1=1
      `;
      countQuery = `
        SELECT COUNT(*) FROM expenses
        JOIN requests ON expenses.request_id = requests.id
        JOIN users ON expenses.user_id = users.id
        JOIN teams ON users.team_id = teams.id
        WHERE 1=1
      `;
      
      if (webmasterFilter) {
        query += ` AND users.id = $${paramIndex}`;
        countQuery += ` AND users.id = $${paramIndex - 2}`; // потому что offset и limit исключаются в countParams
        params.push(webmasterFilter);
        countParams.push(webmasterFilter);
        paramIndex++;
      }
      if (amountFilter) {
        query += ` AND requests.amount = $${paramIndex}`;
        countQuery += ` AND requests.amount = $${paramIndex - 2}`;
        params.push(amountFilter);
        countParams.push(amountFilter);
        paramIndex++;
      }
      if (teamFilter) {
        query += ` AND teams.id = $${paramIndex}`;
        countQuery += ` AND teams.id = $${paramIndex - 2}`;
        params.push(teamFilter);
        countParams.push(teamFilter);
        paramIndex++;
      }
      if (startDate) {
        query += ` AND expenses.created_at >= $${paramIndex}`;
        countQuery += ` AND expenses.created_at >= $${paramIndex - 2}`;
        params.push(startDate);
        countParams.push(startDate);
        paramIndex++;
      }
      if (endDate) {
        query += ` AND expenses.created_at <= $${paramIndex}`;
        countQuery += ` AND expenses.created_at <= $${paramIndex - 2}`;
        params.push(endDate);
        countParams.push(endDate);
        paramIndex++;
      }

      query += ` ORDER BY ${sortByField} ${sortOrder} LIMIT $1 OFFSET $2;`;

    } else if (userRole === 'team_leader' || userRole === 'user') {
      query = `
        SELECT expenses.*, requests.amount, requests.link, users.username 
        FROM expenses
        JOIN requests ON expenses.request_id = requests.id
        JOIN users ON expenses.user_id = users.id
        WHERE users.team_id = $${paramIndex}
      `;
      countQuery = `
        SELECT COUNT(*) FROM expenses
        JOIN requests ON expenses.request_id = requests.id
        JOIN users ON expenses.user_id = users.id
        WHERE users.team_id = $1
      `;
      
      params.push(teamId);
      countParams.push(teamId);
      paramIndex++;

      if (webmasterFilter) {
        query += ` AND users.id = $${paramIndex}`;
        countQuery += ` AND users.id = $${paramIndex - 1}`;
        params.push(webmasterFilter);
        countParams.push(webmasterFilter);
        paramIndex++;
      }
      if (amountFilter) {
        query += ` AND requests.amount = $${paramIndex}`;
        countQuery += ` AND requests.amount = $${paramIndex - 1}`;
        params.push(amountFilter);
        countParams.push(amountFilter);
        paramIndex++;
      }
      if (startDate) {
        query += ` AND expenses.created_at >= $${paramIndex}`;
        countQuery += ` AND expenses.created_at >= $${paramIndex - 1}`;
        params.push(startDate);
        countParams.push(startDate);
        paramIndex++;
      }
      if (endDate) {
        query += ` AND expenses.created_at <= $${paramIndex}`;
        countQuery += ` AND expenses.created_at <= $${paramIndex - 1}`;
        params.push(endDate);
        countParams.push(endDate);
        paramIndex++;
      }

      query += ` ORDER BY ${sortByField} ${sortOrder} LIMIT $1 OFFSET $2;`;

    } else {
      return res.status(403).json({ error: 'Access denied' });
    }

    const result = await pool.query(query, params);
    const countResult = await pool.query(countQuery, countParams);
    const totalItems = parseInt(countResult.rows[0].count, 10);

    res.json({ expenses: result.rows, totalItems });
  } catch (error) {
    console.error('Ошибка при получении расходов:', error);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});


app.get('/api/teams', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name FROM teams');
    res.json({ teams: result.rows });
  } catch (error) {
    console.error('Ошибка при получении команд:', error);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});


//End expenses


//Profile page
app.get('/api/profile', async (req, res) => {
  try {
      const userId = req.session.user.id; // Assuming session contains user_id
      const userProfileQuery = `
          SELECT username, email 
          FROM users 
          WHERE id = $1
      `;

      const result = await pool.query(userProfileQuery, [userId]);
      const user = result.rows[0];

      if (user) {
          res.json(user); // Send back username and email
      } else {
          res.status(404).json({ message: 'User not found' });
      }
  } catch (error) {
      console.error('Error fetching profile:', error);
      res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/profile/update', async (req, res) => {
  const { username, email, password } = req.body;
  const userId = req.session.user.id; // Assuming session contains user_id

  try {
      let updateProfileQuery;
      const queryParams = [username, email, userId];

      // If the password is provided, include it in the update
      if (password) {
          const hashedPassword = await bcrypt.hash(password, 10);
          updateProfileQuery = `
              UPDATE users
              SET username = $1, email = $2, password = $3
              WHERE id = $4
          `;
          queryParams.splice(2, 0, hashedPassword); // Insert hashed password at index 2
      } else {
          updateProfileQuery = `
              UPDATE users
              SET username = $1, email = $2
              WHERE id = $3
          `;
      }

      await pool.query(updateProfileQuery, queryParams);

      res.json({ success: true, message: 'Profile updated successfully' });
  } catch (error) {
      console.error('Error updating profile:', error);
      res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
});

//end of profile page


//Product Page


// Получение всех продуктов
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Добавление нового продукта
app.post('/api/products', async (req, res) => {
  const { name, description, country, payout, capacity, approval_rate, image_url } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO products (name, description, country, payout, capacity, approval_rate, image_url) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [name, description, country, payout, capacity, approval_rate, image_url]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error adding product:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Обновление продукта
app.put('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  const { name, description, country, payout, capacity, approval_rate, image_url } = req.body;
  try {
    const result = await pool.query(
      'UPDATE products SET name = $1, description = $2, country = $3, payout = $4, capacity = $5, approval_rate = $6, image_url = $7 WHERE id = $8 RETURNING *',
      [name, description, country, payout, capacity, approval_rate, image_url, id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Удаление продукта
app.delete('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM products WHERE id = $1', [id]);
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ message: 'Server error' });
  }
});



//end of product page




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
