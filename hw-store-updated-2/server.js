// Simple Node+Express+Socket.io server to power the realtime chat
// Usage:
// 1) npm install
// 2) node server.js
// The client (app.js) connects to SERVER_URL. For local dev use http://localhost:3000

const express = require('express');
const http = require('http');
const {Server} = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {cors:{origin:'*'}});

app.get('/', (req,res)=> res.send('HW Store Chat Server'));

io.on('connection', socket=>{
  console.log('client connected', socket.id);
  socket.on('chat.message', data=>{
    // Broadcast to others
    socket.broadcast.emit('chat.message', data);
  });
  socket.on('disconnect', ()=> console.log('client disconnected', socket.id));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=> console.log('Server running on', PORT));
