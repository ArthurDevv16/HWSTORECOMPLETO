
// Main client-side JS: products, cart, weather, chat wiring
const PRODUCTS = [
  {id:1,name:'Notebook Pro 15',price:5499,tag:'notebook',img:''},
  {id:2,name:'PC Gamer X',price:7999,tag:'pc',img:''},
  {id:3,name:'Monitor 27" 144Hz',price:1299,tag:'monitor',img:''},
  {id:4,name:'Teclado Mecânico',price:299,tag:'perif',img:''},
  {id:5,name:'Mouse Gamer',price:199,tag:'perif',img:''},
  {id:6,name:'SSD NVMe 1TB',price:449,tag:'component',img:''},
];

document.addEventListener('DOMContentLoaded',()=> {
  renderProducts();
  setupProfile();
  setupCart();
  setupWeather();
  setupChat();
  document.getElementById('theme-toggle').addEventListener('click',toggleTheme);
  document.getElementById('toggle-eye').addEventListener('change', e=>{
    const p = document.getElementById('senha');
    p.type = e.target.checked ? 'text' : 'password';
  })
});

function renderProducts(){
  const grid = document.getElementById('product-grid');
  grid.innerHTML = '';
  PRODUCTS.forEach(p=>{
    const card = document.createElement('article');
    card.className='card';
    card.innerHTML = `
      <svg class="product-illustration" viewBox="0 0 300 140" aria-hidden><rect x="6" y="6" rx="10" width="288" height="128" fill="#071733"></rect><text x="18" y="78" font-family="Inter" font-size="18" fill="#9fb8ff">${p.name}</text></svg>
      <h4>${p.name}</h4>
      <div class="price">R$ ${p.price.toFixed(2)}</div>
      <div style="margin-top:8px"><button class="btn" onclick="addToCart(${p.id})">Adicionar</button></div>
    `;
    grid.appendChild(card);
  })
}

// Simple cart using localStorage
function setupCart(){
  window.cart = JSON.parse(localStorage.getItem('hw_cart')||'{}');
  renderCart();
  document.getElementById('checkout').addEventListener('click', ()=>alert('Fluxo de pagamento demo — integrar gateway na migração para backend.'));
}
function addToCart(id){
  const entry = window.cart[id]||{qty:0};
  entry.qty++;
  const prod = PRODUCTS.find(p=>p.id===id);
  entry.name = prod.name; entry.price = prod.price;
  window.cart[id] = entry;
  localStorage.setItem('hw_cart', JSON.stringify(window.cart));
  renderCart();
}
function renderCart(){
  const container = document.getElementById('cart-items');
  container.innerHTML = '';
  const keys = Object.keys(window.cart);
  if(!keys.length){ container.innerHTML = '<div class="muted">Seu carrinho está vazio.</div>'; return;}
  keys.forEach(k=>{
    const it = window.cart[k];
    const div = document.createElement('div');
    div.className = 'card';
    div.innerHTML = `<strong>${it.name}</strong> — R$ ${(it.price).toFixed(2)} x ${it.qty} <button onclick="removeOne(${k})">-</button>`;
    container.appendChild(div);
  })
}
function removeOne(id){
  if(!window.cart[id]) return;
  window.cart[id].qty--;
  if(window.cart[id].qty<=0) delete window.cart[id];
  localStorage.setItem('hw_cart', JSON.stringify(window.cart));
  renderCart();
}

/* THEME */
function toggleTheme(){
  document.documentElement.classList.toggle('light-mode');
  // simple persistent
  localStorage.setItem('hw_theme', document.documentElement.classList.contains('light-mode') ? 'light' : 'dark');
}

/* PROFILE */
function setupProfile(){
  // load theme
  const theme = localStorage.getItem('hw_theme');
  if(theme==='light') document.documentElement.classList.add('light-mode');
}

/* WEATHER */
function setupWeather(){
  const btn = document.getElementById('get-weather');
  btn.addEventListener('click', async ()=>{
    const city = document.getElementById('city-input').value.trim();
    if(!city) return alert('Digite uma cidade, ex: São Paulo,BR');
    await fetchWeather(city);
  });
  // try default
  const last = localStorage.getItem('hw_city');
  if(last) fetchWeather(last);
}
async function fetchWeather(city){
  const widget = document.getElementById('weather-widget');
  widget.classList.add('loading');
  try{
    // config.js must expose OPENWEATHER_API_KEY
    if(!window.CONFIG || !window.CONFIG.OPENWEATHER_API_KEY) throw new Error('Coloque sua OPENWEATHER_API_KEY em config.js');
    const key = window.CONFIG.OPENWEATHER_API_KEY;
    const url = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=metric&lang=pt_br&appid=${key}`;
    const res = await fetch(url);
    if(!res.ok) throw new Error('Cidade não encontrada ou chave inválida');
    const j = await res.json();
    document.getElementById('city').textContent = j.name + ', ' + j.sys.country;
    document.getElementById('desc').textContent = j.weather[0].description;
    document.getElementById('temp').textContent = Math.round(j.main.temp) + '°C';
    localStorage.setItem('hw_city', city);
  }catch(err){
    alert('Erro no clima: ' + err.message);
  }finally{
    widget.classList.remove('loading');
  }
}

/* CHAT (client) - uses socket.io - run the included server for full real-time support */
function setupChat(){
  const SERVER = window.CONFIG && window.CONFIG.SERVER_URL ? window.CONFIG.SERVER_URL : 'http://localhost:3000';
  const socket = io(SERVER, { transports: ['websocket','polling'] });
  const messages = document.getElementById('messages');
  const form = document.getElementById('chat-form');
  const username = document.getElementById('username');

  socket.on('connect', ()=> {
    addSysMessage('Conectado ao chat.');
  });
  socket.on('disconnect', ()=> addSysMessage('Desconectado.'));

  socket.on('chat.message', data=>{
    addMessage(data.name, data.msg, false);
  });

  form.addEventListener('submit', e=>{
    e.preventDefault();
    const msg = document.getElementById('msg').value.trim();
    const name = username.value.trim() || 'Anon';
    if(!msg) return;
    socket.emit('chat.message', {name, msg});
    addMessage(name, msg, true);
    document.getElementById('msg').value = '';
  });

  function addMessage(name, msg, me){
    const el = document.createElement('div');
    el.className = 'msg ' + (me ? 'me' : 'other');
    el.innerHTML = '<strong>'+escapeHtml(name)+'</strong><div>'+escapeHtml(msg)+'</div>';
    messages.appendChild(el);
    messages.scrollTop = messages.scrollHeight;
  }
  function addSysMessage(text){
    const el = document.createElement('div');
    el.className = 'muted';
    el.style.padding = '6px';
    el.textContent = text;
    messages.appendChild(el);
    messages.scrollTop = messages.scrollHeight;
  }
}
function escapeHtml(s){ return s.replace(/[&<>"]/g, c=> ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
