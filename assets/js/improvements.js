function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }

// improvements.js with Socket.IO chat
(() => {
  'use strict';

  async function safeFetch(url, opts = {}, timeout = 8000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(url, {...opts, signal: controller.signal});
      clearTimeout(id);
      if (!res.ok) throw new Error('Network response not ok: ' + res.status);
      return await res.json();
    } catch (e) {
      clearTimeout(id);
      throw e;
    }
  }

  async function loadWeather() {
    const panel = document.getElementById('weather-panel');
    if (!panel) return;
    const city = panel.dataset.city || 'São Paulo';
    const apiKey = panel.dataset.owapikey || '';
    panel.innerHTML = '<div class="small">Carregando clima...</div>';
    if (!apiKey) {
      panel.innerHTML = '<div class="small">OpenWeather API key não definida.</div>';
      return;
    }
    const url = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=metric&lang=pt_br&appid=${apiKey}`;
    try {
      const data = await safeFetch(url, {}, 10000);
      panel.innerHTML = `
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <div class="small">Clima em</div>
              <strong>${data.name}, ${data.sys?.country || ''}</strong>
              <div class="small">${data.weather?.[0]?.description || ''}</div>
            </div>
            <div style="text-align:right">
              <div style="font-size:1.6rem"><strong>${Math.round(data.main.temp)}°C</strong></div>
              <div class="small">Sensação ${Math.round(data.main.feels_like)}°C</div>
            </div>
          </div>
        </div>
      `;
    } catch (e) {
      panel.innerHTML = '<div class="small">Erro ao buscar clima: ' + (e.message || e) + '</div>';
    }
  }

  function setupChat() {
    const chat = document.getElementById('chatbox');
    if (!chat) return;
    chat.innerHTML = `
      <div class="card">
        <h3>Chat</h3>
        <div class="chat-messages" id="chat-messages" aria-live="polite"></div>
        <div class="flex" style="margin-top:8px">
          <input id="chat-input" placeholder="Mensagem..." style="flex:1;padding:8px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);background:transparent;color:var(--text)"/>
          <button id="chat-send" style="padding:8px 12px;border-radius:8px;border:none;background:var(--accent);color:#07203a">Enviar</button>
        </div>
      </div>
    `;

    const list = document.getElementById('chat-messages');
    const input = document.getElementById('chat-input');
    const send = document.getElementById('chat-send');

    // Inject Socket.IO script tag dynamically
    const s = document.createElement("script");
    s.src = "/socket.io/socket.io.js";
    document.body.appendChild(s);

    s.onload = () => {
      const socket = io();

      socket.on("connect", () => {
        const d = document.createElement("div");
        d.className = "chat-message";
        d.textContent = "Conectado ao servidor.";
        list.appendChild(d);
      });

      socket.on("chat-message", msg => {
        const d = document.createElement("div");
        d.className = "chat-message";
        d.textContent = msg;
        list.appendChild(d);
        list.scrollTop = list.scrollHeight;
      });

      send.addEventListener("click", () => {
        const v = input.value.trim();
        if (!v) return;
        socket.emit("chat-message", v);
        const d = document.createElement("div");
        d.className = "chat-message user";
        d.textContent = v;
        list.appendChild(d);
        list.scrollTop = list.scrollHeight;
        input.value = "";
      });

      input.addEventListener("keydown", e => {
        if (e.key === "Enter") send.click();
      });
    };
  }

  function preventOverflow() {
    document.documentElement.style.overflowX = 'hidden';
  }

  document.addEventListener('DOMContentLoaded', () => {
    preventOverflow();
    loadWeather();
    setupChat();
  });
})();
