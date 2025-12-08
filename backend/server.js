require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cookieSession = require('cookie-session');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const User = require('./models/User');

// fetch compatível com Render
const fetch = (...args) =>
  import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
const server = http.createServer(app);

/* =====================================
   SOCKET.IO
===================================== */
const io = new Server(server, {
  cors: { origin: true, methods: ['GET', 'POST'] },
});

io.on('connection', (socket) => {
  socket.on('chat-message', (msg) => io.emit('chat-message', msg));
});

/* =====================================
   MIDDLEWARES
===================================== */
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());

/* =====================================
   FRONTEND
===================================== */
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

/* =====================================
   MONGODB
===================================== */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('Mongo conectado'))
  .catch((e) => console.error(e));

/* =====================================
   SESSION + PASSPORT
===================================== */
app.use(
  cookieSession({
    name: 'session',
    keys: [process.env.SESSION_SECRET],
    maxAge: 24 * 60 * 60 * 1000,
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/api/auth/google/callback`,
    },
    async (_, __, profile, done) => {
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          name: profile.displayName,
          email: profile.emails?.[0]?.value,
        });
      }
      done(null, user);
    }
  )
);

/* =====================================
   AUTH
===================================== */
app.get(
  '/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get(
  '/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.redirect(`/?token=${token}`);
  }
);

/* =====================================
   LOGIN LOCAL
===================================== */
app.post('/api/auth/login', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.status(401).json({ message: 'Usuário não encontrado' });

  const token = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({ token, user });
});

/* =====================================
   USER
===================================== */
app.get('/api/me', async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const data = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(data.id);
    res.json(user);
  } catch {
    res.status(401).json({ message: 'Token inválido' });
  }
});

/* =====================================
   ✅ OPENWEATHER (FUNCIONANDO)
===================================== */
app.get('/api/weather/:city', async (req, res) => {
  try {
    if (!process.env.OPENWEATHER_API_KEY) {
      return res.status(500).json({ error: 'API KEY ausente' });
    }

    const city = req.params.city;
    const url =
      `https://api.openweathermap.org/data/2.5/weather` +
      `?q=${encodeURIComponent(city)}` +
      `&units=metric&appid=${process.env.OPENWEATHER_API_KEY}`;

    const response = await fetch(url);
    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erro ao buscar clima' });
  }
});

/* =====================================
   START SERVER (RENDER)
===================================== */
const PORT = process.env.PORT || 4000;
server.listen(PORT, () =>
  console.log('Servidor rodando na porta ' + PORT)
);
