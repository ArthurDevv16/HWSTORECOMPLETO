
// server.js - simple Express + Socket.IO server for the HW store project
const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Basic rate limiter for API endpoints (prevents abuse)
const apiLimiter = rateLimit({
  windowMs: 10 * 1000, // 10 seconds
  max: 50, // limit each IP to 50 requests per windowMs
});

app.use('/api/', apiLimiter);

// Serve static files from 'public' (we'll map to project root)
app.use(express.static(path.join(__dirname, '/')));

// Simple health endpoint
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Socket.IO chat handling with rooms and usernames
io.on('connection', (socket) => {
  console.log('socket connected:', socket.id);

  socket.on('join', ({ room = 'global', username = 'Anon' } = {}) => {
    socket.join(room);
    socket.data.username = username;
    socket.data.room = room;
    socket.to(room).emit('chat-message', `${username} entrou na sala ${room}.`);
    socket.emit('chat-message', `Bem-vindo(a), ${username}! Sala: ${room}`);
  });

  socket.on('chat-message', (msg) => {
    const username = socket.data.username || 'Anon';
    const room = socket.data.room || 'global';
    const payload = { username, text: msg, ts: Date.now() };
    // Broadcast to room (including sender)
    io.to(room).emit('chat-message', payload);
  });

  socket.on('disconnect', () => {
    const username = socket.data.username || 'Anon';
    const room = socket.data.room || 'global';
    socket.to(room).emit('chat-message', `${username} saiu da sala ${room}.`);
    console.log('socket disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
