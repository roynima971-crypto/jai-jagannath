const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOTEL_NAME = 'JAI JAGANNATH';
const JWT_SECRET = process.env.JWT_SECRET;
const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
if (!JWT_SECRET || (isProduction && JWT_SECRET.length < 32)) {
  throw new Error('Set JWT_SECRET to a random secret of at least 32 characters');
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 12) {
  throw new Error('Set ADMIN_EMAIL and an ADMIN_PASSWORD of at least 12 characters');
}
if (Boolean(process.env.OWNER_EMAIL) !== Boolean(process.env.OWNER_PASSWORD)) {
  throw new Error('Set both OWNER_EMAIL and OWNER_PASSWORD, or leave both empty');
}
if (process.env.OWNER_PASSWORD && process.env.OWNER_PASSWORD.length < 12) {
  throw new Error('OWNER_PASSWORD must be at least 12 characters');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30000
});

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
const bookingLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false });

function cleanEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}
function validDate(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`)) && new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10) === value;
}
function validImageUrl(value) {
  if (!value) return '';
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) && value.length <= 2048 ? value : null;
  } catch { return null; }
}
function issueToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}
function setSession(res, user) {
  res.cookie('jj_session', issueToken(user), {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}
function readCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index >= 0 && part.slice(0, index).trim() === name) return decodeURIComponent(part.slice(index + 1).trim());
  }
  return '';
}
async function requireAuth(req, res, next) {
  try {
    const token = readCookie(req, 'jj_session');
    if (!token) return res.status(401).json({ error: 'Please sign in first.' });
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT id, name, email, role FROM users WHERE id = $1', [payload.sub]);
    if (!result.rowCount) return res.status(401).json({ error: 'Session is no longer valid.' });
    req.user = result.rows[0];
    next();
  } catch {
    res.clearCookie('jj_session', { httpOnly: true, secure: isProduction, sameSite: 'lax', path: '/' });
    return res.status(401).json({ error: 'Please sign in again.' });
  }
}
function requireAdmin(req, res, next) {
  if (!['hotel_owner', 'super_admin'].includes(req.user.role)) return res.status(403).json({ error: 'Admin access required.' });
  next();
}
function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email, role: user.role };
}
function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

async function initDatabase() {
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('customer', 'hotel_owner', 'super_admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS rooms (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
      description TEXT NOT NULL DEFAULT '',
      price NUMERIC(10,2) NOT NULL CHECK (price > 0),
      capacity INTEGER NOT NULL DEFAULT 2 CHECK (capacity BETWEEN 1 AND 20),
      image_url TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'maintenance')),
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS bookings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE RESTRICT,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      check_in DATE NOT NULL,
      check_out DATE NOT NULL,
      guest_count INTEGER NOT NULL CHECK (guest_count BETWEEN 1 AND 20),
      total_amount NUMERIC(10,2) NOT NULL CHECK (total_amount > 0),
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'cancelled', 'checked_in', 'checked_out')),
      payment_status TEXT NOT NULL DEFAULT 'unpaid' CHECK (payment_status IN ('unpaid', 'pending', 'paid', 'failed', 'refunded')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK (check_out > check_in)
    );
    CREATE INDEX IF NOT EXISTS bookings_room_dates_idx ON bookings (room_id, check_in, check_out);
    CREATE INDEX IF NOT EXISTS bookings_user_created_idx ON bookings (user_id, created_at DESC);
  `);
  await seedAccount(process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD, 'super_admin', 'JAI JAGANNATH Super Admin');
  if (process.env.OWNER_EMAIL) await seedAccount(process.env.OWNER_EMAIL, process.env.OWNER_PASSWORD, 'hotel_owner', 'JAI JAGANNATH Hotel Owner');
  const rooms = await pool.query('SELECT count(*)::int AS count FROM rooms');
  if (rooms.rows[0].count === 0) {
    await pool.query(`INSERT INTO rooms (name, description, price, capacity, image_url) VALUES
      ('Deluxe Double Room', 'Comfortable double bed, air conditioning and Wi-Fi.', 2500, 2, 'https://images.unsplash.com/photo-1611892440504-42a792e24d32?auto=format&fit=crop&w=1200&q=80'),
      ('Family Room', 'A spacious room for a relaxing family stay.', 3800, 4, 'https://images.unsplash.com/photo-1590490360182-c33d57733427?auto=format&fit=crop&w=1200&q=80'),
      ('Premium Suite', 'A premium suite with a comfortable sitting area.', 5200, 3, 'https://images.unsplash.com/photo-1505693416388-ac5ce068fe85?auto=format&fit=crop&w=1200&q=80')`);
  }
}
async function seedAccount(emailValue, password, role, name) {
  const email = cleanEmail(emailValue);
  if (!email || !password) return;
  const hash = await bcrypt.hash(password, 12);
  await pool.query(
    `INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4)
     ON CONFLICT (email) DO NOTHING`, [name, email, hash, role]
  );
}

app.get('/api/health', (req, res) => res.json({ ok: true, hotel: HOTEL_NAME }));
app.get('/api/rooms', asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`SELECT id, name, description, price, capacity, image_url AS "imageUrl", status
    FROM rooms WHERE is_active = true ORDER BY created_at, name`);
  res.json(rows);
}));
app.get('/api/me', asyncRoute(async (req, res) => {
  const token = readCookie(req, 'jj_session');
  if (!token) return res.json({ user: null });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT id, name, email, role FROM users WHERE id = $1', [payload.sub]);
    return res.json({ user: result.rowCount ? publicUser(result.rows[0]) : null });
  } catch { return res.json({ user: null }); }
}));

app.post('/api/auth/register', authLimiter, asyncRoute(async (req, res) => {
  const { name, password } = req.body || {};
  const email = cleanEmail(req.body?.email);
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 120 || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'Enter a valid name and email address.' });
  }
  if (typeof password !== 'string' || password.length < 12 || password.length > 200) {
    return res.status(400).json({ error: 'Password must be at least 12 characters.' });
  }
  const hash = await bcrypt.hash(password, 12);
  try {
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
      [name.trim(), email, hash, 'customer']
    );
    setSession(res, result.rows[0]);
    res.status(201).json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'An account with that email already exists.' });
    throw error;
  }
}));
app.post('/api/auth/login', authLimiter, asyncRoute(async (req, res) => {
  const email = cleanEmail(req.body?.email);
  const password = req.body?.password;
  if (!email || typeof password !== 'string') return res.status(400).json({ error: 'Enter your email and password.' });
  const result = await pool.query('SELECT id, name, email, password_hash, role FROM users WHERE email = $1', [email]);
  if (!result.rowCount || !(await bcrypt.compare(password, result.rows[0].password_hash))) {
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  }
  setSession(res, result.rows[0]);
  res.json({ user: publicUser(result.rows[0]) });
}));
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('jj_session', { httpOnly: true, secure: isProduction, sameSite: 'lax', path: '/' });
  res.json({ ok: true });
});

app.post('/api/bookings', requireAuth, bookingLimiter, asyncRoute(async (req, res) => {
  const { roomId, checkIn, checkOut } = req.body || {};
  const guestCount = Number(req.body?.guestCount);
  if (typeof roomId !== 'string' || !validDate(checkIn) || !validDate(checkOut) || checkOut <= checkIn || !Number.isInteger(guestCount) || guestCount < 1 || guestCount > 20) {
    return res.status(400).json({ error: 'Enter valid stay dates and guest count.' });
  }
  const today = new Date().toISOString().slice(0, 10);
  if (checkIn < today) return res.status(400).json({ error: 'Check-in must be today or a future date.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const roomResult = await client.query('SELECT * FROM rooms WHERE id = $1 AND is_active = true FOR UPDATE', [roomId]);
    if (!roomResult.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Room not found.' });
    }
    const room = roomResult.rows[0];
    if (room.status !== 'available' || guestCount > room.capacity) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'This room is unavailable or does not fit the guest count.' });
    }
    const conflict = await client.query(`SELECT 1 FROM bookings WHERE room_id = $1 AND status <> 'cancelled'
      AND check_in < $3::date AND check_out > $2::date LIMIT 1`, [roomId, checkIn, checkOut]);
    if (conflict.rowCount) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'This room is already booked for some of those dates.' });
    }
    const nights = (Date.parse(`${checkOut}T00:00:00Z`) - Date.parse(`${checkIn}T00:00:00Z`)) / 86400000;
    const amount = (Number(room.price) * nights).toFixed(2);
    const booking = await client.query(`INSERT INTO bookings (room_id, user_id, check_in, check_out, guest_count, total_amount)
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, room_id AS "roomId", check_in AS "checkIn", check_out AS "checkOut",
      guest_count AS "guestCount", total_amount AS "totalAmount", status, payment_status AS "paymentStatus"`,
      [roomId, req.user.id, checkIn, checkOut, guestCount, amount]);
    await client.query('COMMIT');
    res.status(201).json({ booking: { ...booking.rows[0], roomName: room.name } });
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
}));
app.get('/api/bookings/mine', requireAuth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`SELECT b.id, r.name AS "roomName", b.check_in AS "checkIn", b.check_out AS "checkOut",
    b.guest_count AS "guestCount", b.total_amount AS "totalAmount", b.status, b.payment_status AS "paymentStatus"
    FROM bookings b JOIN rooms r ON r.id = b.room_id WHERE b.user_id = $1 ORDER BY b.created_at DESC`, [req.user.id]);
  res.json(rows);
}));
app.get('/api/admin/summary', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const result = await pool.query(`SELECT (SELECT count(*)::int FROM rooms WHERE is_active = true) AS rooms,
    (SELECT count(*)::int FROM bookings WHERE status <> 'cancelled') AS bookings,
    (SELECT count(*)::int FROM bookings WHERE status = 'pending') AS pending,
    (SELECT COALESCE(sum(total_amount), 0)::numeric(12,2) FROM bookings WHERE status IN ('confirmed','checked_in','checked_out')) AS confirmed_revenue`);
  res.json(result.rows[0]);
}));
app.get('/api/admin/bookings', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`SELECT b.id, r.name AS "roomName", u.name AS "guestName", u.email,
    b.check_in AS "checkIn", b.check_out AS "checkOut", b.guest_count AS "guestCount", b.total_amount AS "totalAmount",
    b.status, b.payment_status AS "paymentStatus", b.created_at AS "createdAt"
    FROM bookings b JOIN rooms r ON r.id = b.room_id JOIN users u ON u.id = b.user_id ORDER BY b.created_at DESC LIMIT 300`);
  res.json(rows);
}));
app.post('/api/admin/rooms', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const { name, description = '', imageUrl = '', status = 'available' } = req.body || {};
  const price = Number(req.body?.price);
  const capacity = Number(req.body?.capacity);
  const safeImage = validImageUrl(imageUrl);
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 120 || typeof description !== 'string' || description.length > 2000 || !Number.isFinite(price) || price <= 0 || price > 10000000 || !Number.isInteger(capacity) || capacity < 1 || capacity > 20 || safeImage === null || !['available', 'maintenance'].includes(status)) {
    return res.status(400).json({ error: 'Check the room fields and try again.' });
  }
  const { rows } = await pool.query(`INSERT INTO rooms (name, description, price, capacity, image_url, status)
    VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name, description, price, capacity, image_url AS "imageUrl", status`,
    [name.trim(), description.trim(), price, capacity, safeImage, status]);
  res.status(201).json(rows[0]);
}));
app.put('/api/admin/rooms/:id', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const { name, description = '', imageUrl = '', status } = req.body || {};
  const price = Number(req.body?.price);
  const capacity = Number(req.body?.capacity);
  const safeImage = validImageUrl(imageUrl);
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 120 || typeof description !== 'string' || description.length > 2000 || !Number.isFinite(price) || price <= 0 || price > 10000000 || !Number.isInteger(capacity) || capacity < 1 || capacity > 20 || safeImage === null || !['available', 'maintenance'].includes(status)) {
    return res.status(400).json({ error: 'Check the room fields and try again.' });
  }
  const { rows } = await pool.query(`UPDATE rooms SET name=$1, description=$2, price=$3, capacity=$4, image_url=$5, status=$6
    WHERE id=$7 AND is_active=true RETURNING id, name, description, price, capacity, image_url AS "imageUrl", status`,
    [name.trim(), description.trim(), price, capacity, safeImage, status, req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Room not found.' });
  res.json(rows[0]);
}));
app.delete('/api/admin/rooms/:id', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const result = await pool.query('UPDATE rooms SET is_active=false WHERE id=$1 AND is_active=true', [req.params.id]);
  if (!result.rowCount) return res.status(404).json({ error: 'Room not found.' });
  res.json({ ok: true });
}));
app.patch('/api/admin/bookings/:id', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const { status } = req.body || {};
  if (!['pending', 'confirmed', 'cancelled', 'checked_in', 'checked_out'].includes(status)) return res.status(400).json({ error: 'Invalid booking status.' });
  const { rows } = await pool.query(`UPDATE bookings SET status=$1 WHERE id=$2
    RETURNING id, status, payment_status AS "paymentStatus"`, [status, req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Booking not found.' });
  res.json(rows[0]);
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found.' }));
app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

initDatabase().then(() => {
  app.listen(PORT, () => console.log(`${HOTEL_NAME} website listening on port ${PORT}`));
}).catch(error => {
  console.error('Database initialization failed:', error);
  process.exit(1);
});

process.on('SIGTERM', async () => { await pool.end(); process.exit(0); });
