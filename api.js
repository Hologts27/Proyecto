const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');

// Mapa global para tokens de usuario
const userTokens = new Map();

const app = express();
app.use(cors());
app.use(express.json());

// Configuración de la base de datos
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'ROOT',
  database: 'CATALOGO'
};

// Rate limiting: 100 requests por 15 minutos por IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Limite de 100 peticiones
  message: { error: 'Demasiadas peticiones, intenta más tarde.' }
});
app.use(limiter);

// Logs HTTP a archivo y consola
const logStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });
app.use(morgan('combined', { stream: logStream }));
app.use(morgan('dev'));

// Si la tabla usuarios no tiene el campo 'role', crear automáticamente al iniciar el servidor
(async () => {
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [cols] = await conn.execute("SHOW COLUMNS FROM usuarios LIKE 'role'");
    if (!cols.length) {
      await conn.execute("ALTER TABLE usuarios ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'");
      console.log('Campo role agregado a la tabla usuarios.');
    }
  } catch (e) {
    console.error('Error verificando/agregando campo role:', e);
  } finally {
    await conn.end();
  }
})();

// Al iniciar el servidor, cargar tokens persistentes de la BD a memoria
(async () => {
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute(`CREATE TABLE IF NOT EXISTS sesiones (
      token VARCHAR(128) PRIMARY KEY,
      user_id INT,
      creado TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    // Cargar tokens existentes
    const [rows] = await conn.execute('SELECT token, user_id FROM sesiones');
    for (const row of rows) {
      // Buscar usuario y rol
      const [users] = await conn.execute('SELECT id, username, role FROM usuarios WHERE id = ?', [row.user_id]);
      if (users.length) {
        userTokens.set(row.token, { id: users[0].id, username: users[0].username, role: users[0].role });
      }
    }
  } catch (e) {
    console.error('Error inicializando sesiones persistentes:', e);
  } finally {
    await conn.end();
  }
})();

// --- USUARIOS ---
// Al registrar usuario, permite especificar rol (solo si es admin autenticado), si no, siempre 'user'
app.post('/register', authenticateToken, requireAdmin, async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [exists] = await conn.execute('SELECT id FROM usuarios WHERE username = ? OR email = ?', [username, email]);
    if (exists.length) return res.status(409).json({ error: 'Usuario o email ya existe' });
    const hash = await bcrypt.hash(password, 10);
    await conn.execute('INSERT INTO usuarios (username, email, password, role) VALUES (?, ?, ?, ?)', [username, email, hash, role || 'user']);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error en el registro' });
  } finally {
    await conn.end();
  }
});

// Registro público (sin token, siempre user)
app.post('/register_public', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [exists] = await conn.execute('SELECT id FROM usuarios WHERE username = ? OR email = ?', [username, email]);
    if (exists.length) return res.status(409).json({ error: 'Usuario o email ya existe' });
    const hash = await bcrypt.hash(password, 10);
    await conn.execute('INSERT INTO usuarios (username, email, password, role) VALUES (?, ?, ?, ?)', [username, email, hash, 'user']);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error en el registro' });
  } finally {
    await conn.end();
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [users] = await conn.execute('SELECT * FROM usuarios WHERE username = ?', [username]);
    if (!users.length) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const user = users[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const token = Math.random().toString(36).slice(2) + Date.now();
    userTokens.set(token, { id: user.id, username: user.username, role: user.role });
    // Guardar token en BD
    await conn.execute('INSERT INTO sesiones (token, user_id) VALUES (?, ?)', [token, user.id]);
    res.json({ ok: true, user: { id: user.id, username: user.username, email: user.email, role: user.role }, token });
  } catch (e) {
    res.status(500).json({ error: 'Error en el login' });
  } finally {
    await conn.end();
  }
});

// Middleware para autenticar token (persistente)
async function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  // Primero busca en memoria
  if (userTokens.has(token)) {
    req.user = userTokens.get(token);
    return next();
  }
  // Si no está en memoria, busca en BD
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT user_id FROM sesiones WHERE token = ?', [token]);
  if (!rows.length) {
    await conn.end();
    return res.status(401).json({ error: 'No autorizado' });
  }
  // Busca usuario y rol
  const [users] = await conn.execute('SELECT id, username, role FROM usuarios WHERE id = ?', [rows[0].user_id]);
  await conn.end();
  if (!users.length) return res.status(401).json({ error: 'No autorizado' });
  req.user = { id: users[0].id, username: users[0].username, role: users[0].role };
  userTokens.set(token, req.user); // cachea en memoria
  next();
}

// --- Middleware para verificar admin ---
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acceso solo para administradores' });
  }
  next();
}

// --- FAVORITOS SERIES ---
// Obtener favoritos
app.get('/favoritos', async (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).json({ error: 'Falta el user_id' });
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT serie_json FROM favoritos WHERE user_id = ?', [user_id]);
  await conn.end();
  res.json(rows.map(r => JSON.parse(r.serie_json)));
});
// Agregar favorito
app.post('/favoritos', async (req, res) => {
  const { user_id, serie } = req.body;
  if (!user_id || !serie || !serie.id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute(
      'INSERT INTO favoritos (user_id, serie_id, serie_json) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE serie_json = VALUES(serie_json)',
      [user_id, serie.id, JSON.stringify(serie)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al guardar favorito' });
  } finally {
    await conn.end();
  }
});
// Eliminar favorito
app.delete('/favoritos', async (req, res) => {
  const { user_id, serie_id } = req.body;
  if (!user_id || !serie_id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('DELETE FROM favoritos WHERE user_id = ? AND serie_id = ?', [user_id, serie_id]);
  await conn.end();
  res.json({ ok: true });
});

// --- FAVORITOS PELICULAS (opcional) ---
app.get('/favoritos_peliculas', async (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).json({ error: 'Falta el user_id' });
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT pelicula_json FROM favoritos_peliculas WHERE user_id = ?', [user_id]);
  await conn.end();
  res.json(rows.map(r => JSON.parse(r.pelicula_json)));
});
app.post('/favoritos_peliculas', async (req, res) => {
  const { user_id, pelicula } = req.body;
  if (!user_id || !pelicula || !pelicula.id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute(
      'INSERT INTO favoritos_peliculas (user_id, pelicula_id, pelicula_json) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE pelicula_json = VALUES(pelicula_json)',
      [user_id, pelicula.id, JSON.stringify(pelicula)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al guardar favorito' });
  } finally {
    await conn.end();
  }
});
app.delete('/favoritos_peliculas', async (req, res) => {
  const { user_id, pelicula_id } = req.body;
  if (!user_id || !pelicula_id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('DELETE FROM favoritos_peliculas WHERE user_id = ? AND pelicula_id = ?', [user_id, pelicula_id]);
  await conn.end();
  res.json({ ok: true });
});

// --- TODO/TAREAS ---
// Obtener tareas
app.get('/todo', async (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).json({ error: 'Falta el user_id' });
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT * FROM todo WHERE user_id = ?', [user_id]);
  await conn.end();
  res.json(rows);
});
// Crear tarea
app.post('/todo', async (req, res) => {
  const { user_id, titulo, descripcion } = req.body;
  if (!user_id || !titulo) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('INSERT INTO todo (user_id, titulo, descripcion) VALUES (?, ?, ?)', [user_id, titulo, descripcion || '']);
  await conn.end();
  res.json({ ok: true });
});
// Actualizar tarea
app.put('/todo/:id', async (req, res) => {
  const id = req.params.id;
  const { titulo, descripcion, completado } = req.body;
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('UPDATE todo SET titulo = ?, descripcion = ?, completado = ? WHERE id = ?', [titulo, descripcion, !!completado, id]);
  await conn.end();
  res.json({ ok: true });
});
// Eliminar tarea
app.delete('/todo/:id', async (req, res) => {
  const id = req.params.id;
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('DELETE FROM todo WHERE id = ?', [id]);
  await conn.end();
  res.json({ ok: true });
});

// --- Cambiar correo electrónico ---
app.post('/update_email', async (req, res) => {
  const { user_id, email } = req.body;
  if (!user_id || !email) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute('UPDATE usuarios SET email = ? WHERE id = ?', [email, user_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al actualizar correo' });
  } finally {
    await conn.end();
  }
});

// --- Cambiar contraseña ---
app.post('/update_password', async (req, res) => {
  const { user_id, old_password, new_password } = req.body;
  if (!user_id || !old_password || !new_password) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [users] = await conn.execute('SELECT password FROM usuarios WHERE id = ?', [user_id]);
    if (!users.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const valid = await bcrypt.compare(old_password, users[0].password);
    if (!valid) return res.status(401).json({ error: 'La contraseña actual no es correcta' });
    const hash = await bcrypt.hash(new_password, 10);
    await conn.execute('UPDATE usuarios SET password = ? WHERE id = ?', [hash, user_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al actualizar contraseña' });
  } finally {
    await conn.end();
  }
});

// --- Rutas de administración ---
// Listar usuarios (solo admin)
app.get('/admin/usuarios', authenticateToken, requireAdmin, async (req, res) => {
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT id, username, email, role FROM usuarios');
  await conn.end();
  res.json(rows);
});
// Cambiar rol de usuario (solo admin)
app.post('/admin/cambiar_rol', authenticateToken, requireAdmin, async (req, res) => {
  const { user_id, role } = req.body;
  if (!user_id || !role) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('UPDATE usuarios SET role = ? WHERE id = ?', [role, user_id]);
  await conn.end();
  res.json({ ok: true });
});
// Eliminar usuario (solo admin)
app.post('/admin/eliminar_usuario', authenticateToken, requireAdmin, async (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('DELETE FROM usuarios WHERE id = ?', [user_id]);
  await conn.end();
  res.json({ ok: true });
});
// Resetear contraseña de usuario (solo admin)
app.post('/admin/reset_password', authenticateToken, requireAdmin, async (req, res) => {
  const { user_id, new_password } = req.body;
  if (!user_id || !new_password) return res.status(400).json({ error: 'Datos incompletos' });
  const hash = await bcrypt.hash(new_password, 10);
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('UPDATE usuarios SET password = ? WHERE id = ?', [hash, user_id]);
  await conn.end();
  res.json({ ok: true });
});
// Logs de acceso (solo admin)
app.get('/admin/logs', authenticateToken, requireAdmin, (req, res) => {
  fs.readFile(path.join(__dirname, 'access.log'), 'utf8', (err, data) => {
    if (err) return res.status(500).json({ error: 'No se pudo leer el log' });
    res.type('text/plain').send(data);
  });
});
// Limpiar logs (solo admin)
app.post('/admin/limpiar_logs', authenticateToken, requireAdmin, (req, res) => {
  fs.writeFile(path.join(__dirname, 'access.log'), '', err => {
    if (err) return res.status(500).json({ error: 'No se pudo limpiar el log' });
    res.json({ ok: true });
  });
});
// Total de favoritos (dashboard)
app.get('/admin/favoritos_total', authenticateToken, requireAdmin, async (req, res) => {
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [rows1] = await conn.execute('SELECT COUNT(*) as total FROM favoritos');
    const [rows2] = await conn.execute('SELECT COUNT(*) as total FROM favoritos_peliculas');
    res.json({ total: (rows1[0].total || 0) + (rows2[0].total || 0) });
  } catch (e) {
    res.status(500).json({ error: 'Error al contar favoritos' });
  } finally {
    await conn.end();
  }
});

// Endpoint para logout (opcional, para limpiar sesión)
app.post('/logout', authenticateToken, async (req, res) => {
  const token = req.headers['authorization'];
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('DELETE FROM sesiones WHERE token = ?', [token]);
  userTokens.delete(token);
  await conn.end();
  res.json({ ok: true });
});

// Puerto
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log('API escuchando en puerto', PORT));
