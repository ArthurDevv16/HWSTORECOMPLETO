require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cookieSession = require('cookie-session');
const cors = require('cors');
const bodyParser = require('body-parser');
const User = require('./models/User');
const jwt = require('jsonwebtoken');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());

// connect mongo
const MONGO = process.env.MONGO_URI || 'mongodb://localhost:27017/hw_store';
mongoose
  .connect(MONGO, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('mongo connected'))
  .catch((e) => console.error(e));

// sessions for passport
app.use(
  cookieSession({
    name: 'session',
    keys: [process.env.SESSION_SECRET || 'devsecret'],
    maxAge: 24 * 60 * 60 * 1000,
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const u = await User.findById(id);
    done(null, u);
  } catch (e) {
    done(e);
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || '<GOOGLE_CLIENT_ID>',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '<GOOGLE_CLIENT_SECRET>',
      callbackURL: process.env.GOOGLE_CALLBACK || 'http://localhost:4000/api/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          user = new User({
            googleId: profile.id,
            name: profile.displayName,
            email: (profile.emails && profile.emails[0] && profile.emails[0].value) || '',
          });
          await user.save();
        }
        done(null, user);
      } catch (e) {
        done(e);
      }
    }
  )
);

// ===============================
//      GOOGLE AUTH ROUTES
// ===============================

app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user._id, name: req.user.name },
      process.env.JWT_SECRET || 'jwtsecret',
      { expiresIn: '7d' }
    );

    const redirectURL =
      process.env.FRONTEND_URL
        ? process.env.FRONTEND_URL + '/?token=' + token
        : 'http://localhost:5173/?token=' + token;

    res.redirect(redirectURL);
  }
);

// ===============================
//      API LOCAL LOGIN (DEMO)
// ===============================
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const u = await User.findOne({ email: username });
  if (!u) return res.status(401).json({ message: 'Usuário não encontrado' });

  const token = jwt.sign(
    { id: u._id, name: u.name },
    process.env.JWT_SECRET || 'jwtsecret',
    { expiresIn: '7d' }
  );

  res.json({ token, user: { id: u._id, name: u.name, email: u.email } });
});

// ===============================
//      USER INFO ROUTE
// ===============================
app.get('/api/me', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'no auth' });

  const token = auth.split(' ')[1];
  try {
    const data = jwt.verify(token, process.env.JWT_SECRET || 'jwtsecret');
    const u = await User.findById(data.id).select('-__v');
    res.json({ user: u });
  } catch (e) {
    res.status(401).json({ message: 'invalid token' });
  }
});

// ===============================
//      WEATHER API (OpenWeather)
// ===============================
app.get('/api/weather/:city', async (req, res) => {
  try {
    const API_KEY = process.env.OPENWEATHER_API_KEY;

    if (!API_KEY) {
      return res.status(500).json({ error: 'API key não definida no backend (.env)' });
    }

    const city = req.params.city;
    const url = `https://api.openweathermap.org/data/2.5/weather?q=${city}&units=metric&appid=${API_KEY}`;

    const response = await fetch(url);
    const data = await response.json();
    res.json(data);

  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar dados do clima.' });
  }
});

// ===============================
//      START SERVER
// ===============================
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('Server listening on', PORT));
