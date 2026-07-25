import { Hono } from 'hono';
import { cors } from 'hono/cors';
import Database from 'better-sqlite3';
import * as crypto from 'node:crypto';

const app = new Hono();

// ========== BANCO DE DADOS ==========
const db = new Database('linfy.db');
db.exec(`
 CREATE TABLE IF NOT EXISTS licencas (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 license_key TEXT UNIQUE NOT NULL,
 plan TEXT NOT NULL,
 max_activations INTEGER DEFAULT 5,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 signature TEXT NOT NULL,
 status TEXT DEFAULT 'ativa',
 comprador TEXT,
 device_id TEXT
 );
 CREATE TABLE IF NOT EXISTS usuarios (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL,
 role TEXT DEFAULT 'admin',
 cota INTEGER DEFAULT 999999
 );
 INSERT OR IGNORE INTO usuarios (username, password, role, cota)
 VALUES ('admin', 'admin123', 'admin', 999999);
`);

// ========== GERADOR LINFY ==========
function gerarChave(plan: 'Pro' | 'Trial' = 'Pro', maxActivations: number = 5, dias: number = 30) {
 const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
 const block = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
 
 const b1 = block(), b2 = block(), b3 = block(), b4 = block();
 const prefixo = plan === 'Pro' ? 'LINFY' : 'TRIAL';
 const licenseKey = `${prefixo}-${b1}-${b2}-${b3}-${b4}`;
 
 const criado = Math.floor(Date.now() / 1000);
 const expira = Math.floor((Date.now() + dias * 24 * 60 * 60 * 1000) / 1000);
 
 const raw = `${licenseKey}|${criado}|${expira}|${maxActivations}`;
 const signature = crypto.createHash('sha256').update(raw).digest('hex').substring(0, 8).toUpperCase();
 
 return { license_key: licenseKey, plan, max_activations: maxActivations, created_at: criado, expires_at: expira, signature };
}

function verificarToken(token: string): boolean {
 return token === 'admin_token' || token.startsWith('admin_');
}

// ========== CORS ==========
app.use('*', cors());

// ========== ROTAS ==========
app.get('/', (c) => c.json({ status: 'LINFY License System', version: '1.0' }));

app.post('/api/login', async (c) => {
 const { username, password } = await c.req.json();
 const user = db.prepare('SELECT * FROM usuarios WHERE username = ? AND password = ?').get(username, password);
 if (!user) return c.json({ erro: 'Credenciais inválidas' }, 401);
 return c.json({ token: `admin_${username}_${Date.now()}`, username });
});

app.post('/api/license/generate', async (c) => {
 const auth = c.req.header('Authorization');
 if (!auth || !auth.startsWith('Bearer ')) return c.json({ erro: 'Token inválido' }, 401);
 const token = auth.slice(7);
 if (!verificarToken(token)) return c.json({ erro: 'Token inválido' }, 401);
 const { plan = 'Pro', maxActivations = 5, durationValue = 30, email } = await c.req.json();
 const lic = gerarChave(plan, maxActivations, durationValue);
 db.prepare(`INSERT INTO licencas (license_key, plan, max_activations, created_at, expires_at, signature, comprador)
 VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
 lic.license_key, plan, maxActivations, lic.created_at, lic.expires_at, lic.signature, email || null);
 return c.json({ ok: true, license_key: lic.license_key, plan: lic.plan, expires_at: new Date(lic.expires_at * 1000).toISOString(), max_activations: lic.max_activations }, 201);
});

app.post('/api/license/validate', async (c) => {
 const { license_key } = await c.req.json();
 if (!license_key) return c.json({ ok: false, erro: 'Chave não fornecida' }, 400);
 
 const row = db.prepare('SELECT * FROM licencas WHERE license_key = ?').get(license_key);
 if (!row) return c.json({ ok: false, valid: false, mensagem: 'Chave não encontrada' }, 404);
 
 const now = Math.floor(Date.now() / 1000);
 if (now > (row as any).expires_at) return c.json({ ok: false, valid: false, mensagem: 'Chave expirada' }, 403);
 if ((row as any).status !== 'ativa') return c.json({ ok: false, valid: false, mensagem: 'Chave revogada' }, 403);
 
 return c.json({ ok: true, valid: true, plan: (row as any).plan, expires_at: new Date((row as any).expires_at * 1000).toISOString(), max_activations: (row as any).max_activations });
});

app.get('/api/license/list', async (c) => {
 const auth = c.req.header('Authorization');
 if (!auth || !auth.startsWith('Bearer ')) return c.json({ erro: 'Token inválido' }, 401);
 const token = auth.slice(7);
 if (!verificarToken(token)) return c.json({ erro: 'Token inválido' }, 401);
 const rows = db.prepare('SELECT license_key, plan, status, expires_at, comprador FROM licencas ORDER BY id DESC').all();
 return c.json((rows as any[]).map((r: any) => ({ license_key: r.license_key, plan: r.plan, status: r.status, expires_at: new Date(r.expires_at * 1000).toISOString(), comprador: r.comprador })));
});

// ========== PAINEL ADMIN ==========
const ADMIN_HTML = `<!DOCTYPE html>
<html><head><title>LINFY Manager</title>
<style>
 * { box-sizing: border-box; margin:0; padding:0; }
 body { font-family: system-ui; background: #0a0a0a; color: #0f0; padding:20px; }
 .container { max-width: 900px; margin:0 auto; }
 .card { background: #1a1a1a; padding:20px; border-radius:10px; margin:12px 0; border:1px solid #0f0; }
 input, select, button { background: #222; color:#0f0; border:1px solid #0f0; padding:10px; margin:4px; border-radius:6px; }
 button { cursor:pointer; }
 button:hover { background:#0f0; color:#0a0a0a; }
 .key { background:#111; padding:12px; border-radius:6px; font-family:monospace; word-break:break-all; margin-top:10px; }
 table { width:100%; border-collapse:collapse; margin-top:10px; }
 td, th { border:1px solid #333; padding:8px; text-align:left; font-size:13px; }
 .hidden { display:none; }
</style></head>
<body>
<div class="container">
 <h1>🔓 LINFY License Manager</h1>
 <div class="card" id="loginCard">
 <h2>Login</h2>
 <input id="user" placeholder="Usuário" value="admin">
 <input id="pass" placeholder="Senha" type="password" value="admin123">
 <button onclick="login()">Entrar</button>
 <div id="loginResult" style="margin-top:10px;"></div>
 </div>
 <div id="adminPanel" class="hidden">
 <div class="card"><h2>Gerar Licença</h2>
 <select id="plan"><option value="Pro">Pro</option><option value="Trial">Trial</option></select>
 <input type="number" id="dias" value="30" placeholder="Dias">
 <input type="number" id="dispositivos" value="5" placeholder="Dispositivos">
 <button onclick="gerarChave()">Gerar</button>
 <div id="resultado" class="key"></div>
 </div>
 <div class="card"><h2>Listar</h2><button onclick="listarChaves()">Atualizar</button><div id="lista"></div></div>
 <div class="card"><h2>Validar</h2>
 <input id="chave_validar" placeholder="LINFY-XXXX-XXXX-XXXX-XXXX" style="width:60%;">
 <button onclick="validarChave()">Validar</button>
 <div id="validacao" class="key"></div>
 </div>
 </div>
</div>
<script>
let token='';
const BASE=window.location.origin;
async function login() {
 const user=document.getElementById('user').value, pass=document.getElementById('pass').value;
 const res=await fetch(BASE+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
 const data=await res.json();
 if(data.token){ token=data.token; document.getElementById('loginResult').innerHTML='✅ Login OK'; document.getElementById('loginCard').style.display='none'; document.getElementById('adminPanel').classList.remove('hidden'); }
 else document.getElementById('loginResult').innerHTML='❌ '+(data.erro||'Erro');
}
async function gerarChave() {
 const plan=document.getElementById('plan').value, dias=parseInt(document.getElementById('dias').value)||30, maxActivations=parseInt(document.getElementById('dispositivos').value)||5;
 const res=await fetch(BASE+'/api/license/generate',{method:'POST',headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({plan,durationValue:dias,maxActivations})});
 const data=await res.json();
 document.getElementById('resultado').innerHTML=data.license_key||'❌ '+JSON.stringify(data);
}
async function listarChaves() {
 const res=await fetch(BASE+'/api/license/list',{headers:{'Authorization':'Bearer '+token}});
 const data=await res.json();
 let html='<table><tr><th>Chave</th><th>Plano</th><th>Status</th><th>Expira</th></tr>';
 data.forEach(i=>{html+='<tr><td>'+i.license_key+'</td><td>'+i.plan+'</td><td>'+i.status+'</td><td>'+i.expires_at+'</td></tr>';});
 html+='</table>'; document.getElementById('lista').innerHTML=html;
}
async function validarChave() {
 const chave=document.getElementById('chave_validar').value;
 const res=await fetch(BASE+'/api/license/validate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({license_key:chave})});
 const data=await res.json();
 document.getElementById('validacao').innerHTML=(data.valid?'✅ Válida':'❌ Inválida')+' — '+(data.mensagem||'');
}
</script>
</body></html>`;

app.get('/admin', (c) => c.html(ADMIN_HTML));

// ========== START ==========
const port = Number(process.env.PORT) || 3000;
console.log(`🚀 LINFY License System running on http://localhost:${port}`);
console.log(`📊 Admin panel: http://localhost:${port}/admin`);

export default {
 port,
 fetch: app.fetch
};
