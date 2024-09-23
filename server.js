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
const nodemailer = require('nodemailer');
// Настройки для базы данных
const dbUser = process.env.DB_USER;
const db = process.env.DB;
const host = process.env.HOST;
const dbPort = process.env.DB_PORT;
const dbPassword = process.env.DB_PASSWORD;
const mailUser = process.env.MAIL_USER
const mailPass = process.env.MAIL_PASS


// Определяем директорию для загрузки файлов
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/images'); // Указываем путь для сохранения изображений
  },
  filename: function (req, file, cb) {
    // Генерация уникального имени файла, сохраняя оригинальное расширение
    const ext = path.extname(file.originalname);
    const filename = `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`;
    cb(null, filename);
  }
});


const upload = multer({ storage: storage });
// Настройка статической директории для доступа к изображениям
app.use('/uploads/images', express.static('uploads/images'));


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
    next();
  } else {
    res.status(401).json({ message: 'Not authorized' });
  }
};

//LoginPage

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


// Маршрут для отправки кода сброса пароля
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  try {
    // Поиск пользователя по email
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'User with this email not found' });
    }

    // Генерация кода сброса пароля (или ссылки с токеном)
    const resetCode = Math.floor(100000 + Math.random() * 900000); // 6-значный код
    const expirationTime = new Date(Date.now() + 15 * 60 * 1000); // 15 минут на сброс

    // Сохранение кода в базе данных
    await pool.query(
      'INSERT INTO verification_codes (email, verification_code, expiration_time) VALUES ($1, $2, $3)',
      [email, resetCode, expirationTime]
    );

    // Отправка кода на почту
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: mailUser,
        pass: mailPass,
      },
    });

    const mailOptions = {
      from: mailUser,
      to: email,
      subject: 'Password Reset Code' ,
      text: `Your password reset code is: ${resetCode}. It will expire in 15 minutes.`,
    };

    await transporter.sendMail(mailOptions);

    res.json({ success: true, message: 'Reset code sent to your email.' });
  } catch (error) {
    console.error('Error sending password reset code:', error);
    res.status(500).json({ success: false, message: 'Failed to send reset code.' });
  }
});

// Маршрут для сброса пароля
app.post('/api/reset-password', async (req, res) => {
  const { email, resetCode, newPassword } = req.body;

  try {
    // Проверяем код сброса
    const codeResult = await pool.query(
      'SELECT * FROM verification_codes WHERE email = $1 AND verification_code = $2 AND expiration_time > NOW()',
      [email, resetCode]
    );
    
    if (codeResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired reset code' });
    }

    // Хешируем новый пароль
    const hashedPassword = bcrypt.hashSync(newPassword, 10);

    // Обновляем пароль пользователя
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);

    // Удаляем использованный код сброса
    await pool.query('DELETE FROM verification_codes WHERE email = $1', [email]);

    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

//end LoginPage


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


// Create a new team
app.post('/teams', async (req, res, next) => {
  const { name } = req.body;

  try {
    // Insert the new team into the database
    const result = await pool.query(
      'INSERT INTO teams (name) VALUES ($1) RETURNING *',
      [name]
    );
    res.status(201).json(result.rows[0]); // Send back the newly created team
  } catch (error) {
    console.error('Error adding team:', error);
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
    let params = [];
    let countQuery = '';
    let countParams = [];

    let paramIndex = 1; // Начинаем с индекса 1

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
        countQuery += ` AND users.id = $${paramIndex}`;
        params.push(webmasterFilter);
        countParams.push(webmasterFilter);
        paramIndex++;
      }
      if (amountFilter) {
        query += ` AND requests.amount = $${paramIndex}`;
        countQuery += ` AND requests.amount = $${paramIndex}`;
        params.push(amountFilter);
        countParams.push(amountFilter);
        paramIndex++;
      }
      if (teamFilter) {
        query += ` AND teams.id = $${paramIndex}`;
        countQuery += ` AND teams.id = $${paramIndex}`;
        params.push(teamFilter);
        countParams.push(teamFilter);
        paramIndex++;
      }
      if (startDate) {
        query += ` AND expenses.created_at >= $${paramIndex}`;
        countQuery += ` AND expenses.created_at >= $${paramIndex}`;
        params.push(startDate);
        countParams.push(startDate);
        paramIndex++;
      }
      if (endDate) {
        query += ` AND expenses.created_at <= $${paramIndex}`;
        countQuery += ` AND expenses.created_at <= $${paramIndex}`;
        params.push(endDate);
        countParams.push(endDate);
        paramIndex++;
      }

      // Добавляем LIMIT и OFFSET в конец
      query += ` ORDER BY ${sortByField} ${sortOrder} LIMIT $${paramIndex} OFFSET $${paramIndex + 1};`;
      params.push(limit, offset);

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
        WHERE users.team_id = $${paramIndex}
      `;
      
      params.push(teamId);
      countParams.push(teamId);
      paramIndex++;

      if (webmasterFilter) {
        query += ` AND users.id = $${paramIndex}`;
        countQuery += ` AND users.id = $${paramIndex}`;
        params.push(webmasterFilter);
        countParams.push(webmasterFilter);
        paramIndex++;
      }
      if (amountFilter) {
        query += ` AND requests.amount = $${paramIndex}`;
        countQuery += ` AND requests.amount = $${paramIndex}`;
        params.push(amountFilter);
        countParams.push(amountFilter);
        paramIndex++;
      }
      if (startDate) {
        query += ` AND expenses.created_at >= $${paramIndex}`;
        countQuery += ` AND expenses.created_at >= $${paramIndex}`;
        params.push(startDate);
        countParams.push(startDate);
        paramIndex++;
      }
      if (endDate) {
        query += ` AND expenses.created_at <= $${paramIndex}`;
        countQuery += ` AND expenses.created_at <= $${paramIndex}`;
        params.push(endDate);
        countParams.push(endDate);
        paramIndex++;
      }

      // Добавляем LIMIT и OFFSET в конец
      query += ` ORDER BY ${sortByField} ${sortOrder} LIMIT $${paramIndex} OFFSET $${paramIndex + 1};`;
      params.push(limit, offset);

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
          SELECT username, email, image
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

app.post('/api/profile/update', upload.single('image'), async (req, res) => {
  const { username, email, password } = req.body;
  const userId = req.session.user.id;
  let imageUrl = req.file ? `/uploads/images/${req.file.filename}` : null; // URL для аватарки

  try {
    let updateProfileQuery;
    let queryParams = [username, email, userId];

    // Если аватарка была загружена
    if (imageUrl) {
      // Если пароль предоставлен, обновляем и его
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updateProfileQuery = `
          UPDATE users
          SET username = $1, email = $2, password = $3, image = $4
          WHERE id = $5
        `;
        queryParams = [username, email, hashedPassword, imageUrl, userId];
      } else {
        updateProfileQuery = `
          UPDATE users
          SET username = $1, email = $2, image = $3
          WHERE id = $4
        `;
        queryParams = [username, email, imageUrl, userId];
      }
    } else {
      // Если аватарка не загружена, оставляем только обновление других полей
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updateProfileQuery = `
          UPDATE users
          SET username = $1, email = $2, password = $3
          WHERE id = $4
        `;
        queryParams = [username, email, hashedPassword, userId];
      } else {
        updateProfileQuery = `
          UPDATE users
          SET username = $1, email = $2
          WHERE id = $3
        `;
      }
    }

    await pool.query(updateProfileQuery, queryParams);

    // Возвращаем новый URL изображения
    res.json({ success: true, message: 'Profile updated successfully', imageUrl });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
});


// Route for sending the password reset code
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    // Find user by email
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'User with this email not found' });
    }

    // Generate a 6-digit reset code
    const resetCode = Math.floor(100000 + Math.random() * 900000); // 6-digit code
    const expirationTime = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes expiration

    // Save the reset code in the database
    await pool.query(
      'INSERT INTO verification_codes (email, verification_code, expiration_time) VALUES ($1, $2, $3)',
      [email, resetCode, expirationTime]
    );

    // Send the reset code via email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: mailUser,
        pass: mailPass,
      },
    });

    const mailOptions = {
      from: mailUser,
      to: email,
      subject: 'Password Reset Code',
      text: `Your password reset code is: ${resetCode}. It will expire in 15 minutes.`,
    };

    await transporter.sendMail(mailOptions);

    res.json({ success: true, message: 'Reset code sent to your email.' });
  } catch (error) {
    console.error('Error sending password reset code:', error);
    res.status(500).json({ success: false, message: 'Failed to send reset code.' });
  }
});
// Route for verifying the reset code and updating the password
app.post('/api/reset-password', async (req, res) => {
  const { email, resetCode, newPassword } = req.body;

  try {
    // Check if the reset code is valid and not expired
    const result = await pool.query(
      'SELECT * FROM verification_codes WHERE email = $1 AND verification_code = $2 AND expiration_time > NOW()',
      [email, resetCode]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired reset code.' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);

    // Optionally delete the reset code after successful password reset
    await pool.query('DELETE FROM verification_codes WHERE email = $1', [email]);

    res.json({ success: true, message: 'Password reset successfully.' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ success: false, message: 'Failed to reset password.' });
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

// Маршрут для добавления продукта
app.post('/api/products', upload.single('image'), async (req, res) => {
  const { name, description, country, avgPayout, capacity, approvalRate } = req.body;
  const image_url = req.file ? `/uploads/images/${req.file.filename}` : null;

  try {
    const result = await pool.query(
      'INSERT INTO products (name, description, country, payout, capacity, approval_rate, image_url) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [name, description, country, avgPayout, capacity, approvalRate, image_url]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error adding product:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// Получение продукта по ID
app.get('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      console.log('Продукт не найден'); // Логируем, если продукт не найден
      return res.status(404).json({ message: 'Product not found' });
    }
    console.log('Продукт найден:', result.rows[0]); // Логируем найденный продукт
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Ошибка при получении продукта:', error); // Логируем ошибку
    res.status(500).json({ message: 'Server error' });
  }
});


// Обновление продукта с поддержкой изменения изображения
app.put('/api/products/:id', upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, description, country, payout, capacity, approval_rate } = req.body;
  const image_url = req.file ? `/uploads/images/${req.file.filename}` : req.body.existingImage; // Используем загруженное изображение или старое

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


//Adding User
const verificationCodes = {};

app.post('/api/admin/add-user', async (req, res) => {
  const { username, email, password, team_id } = req.body;
  const code = Math.floor(1000 + Math.random() * 9000); // Генерация 4-значного кода
  const expirationTime = new Date(Date.now() + 10 * 60 * 1000); // Код истекает через 10 минут

  try {
    // Проверяем, существует ли пользователь с таким email или именем
    const existingUser = await pool.query(
      'SELECT * FROM users WHERE email = $1 OR username = $2',
      [email, username]
    );

    // Если пользователь уже существует, возвращаем ошибку
    if (existingUser.rows.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Пользователь с таким email или именем уже существует',
      });
    }

    // Сохраняем код верификации и время истечения
    await pool.query(
      'INSERT INTO verification_codes (email, verification_code, expiration_time) VALUES ($1, $2, $3)',
      [email, code, expirationTime]
    );

    // Отправляем код верификации по email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: mailUser,
        pass: mailPass,
      },
    });

    const mailOptions = {
      from: 'confirmation@gmail.com',
      to: email,
      subject: 'Your verification code',
      text: `Ваш код подтверждения: ${code}. Он истекает через 10 минут.`,
    };

    await transporter.sendMail(mailOptions);

    res.json({ success: true });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ success: false, message: 'Не удалось отправить код подтверждения' });
  }
});

app.post('/api/admin/verify-code', async (req, res) => {
  const { email, verificationCode, username, password, team_id } = req.body;

  try {
    const result = await pool.query(
      'SELECT verification_code, expiration_time FROM verification_codes WHERE email = $1',
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'Verification code not found' });
    }

    const { verification_code, expiration_time } = result.rows[0];

    if (new Date() > expiration_time) {
      return res.status(400).json({ success: false, message: 'Verification code expired' });
    }

    if (verification_code !== verificationCode) {
      return res.status(400).json({ success: false, message: 'Invalid verification code' });
    }

    // Если код правильный и не просрочен, создаем пользователя
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, email, password, role, team_id) VALUES ($1, $2, $3, $4, $5)',
      [username, email, hashedPassword, 'user', team_id]
    );

    // Удаляем запись с кодом после успешной верификации
    await pool.query('DELETE FROM verification_codes WHERE email = $1', [email]);

    res.json({ success: true });
  } catch (error) {
    console.error('Error verifying code:', error);
    res.status(500).json({ success: false, message: 'Failed to verify code' });
  }
});


//end of adding user



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
