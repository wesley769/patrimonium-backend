/**
 * Patrimonium Finance — API Client
 * Inclua este script ANTES do fechamento do </body> em todos os HTMLs
 * <script src="api.js"></script>
 */

const API_URL = window.PATRIMONIUM_API_URL || 'https://patrimonium-backend.onrender.com';

// ─── TOKEN ──────────────────────────────────────────────
const Auth = {
  getToken: () => localStorage.getItem('pf_token'),
  setToken: (t) => localStorage.setItem('pf_token', t),
  getUser:  () => { try { return JSON.parse(localStorage.getItem('pf_user')); } catch { return null; } },
  setUser:  (u) => localStorage.setItem('pf_user', JSON.stringify(u)),
  clear:    () => { localStorage.removeItem('pf_token'); localStorage.removeItem('pf_user'); localStorage.removeItem('pf_empresa_id'); },
  isAdmin:  () => Auth.getUser()?.role === 'admin',
  getEmpresaId: () => localStorage.getItem('pf_empresa_id'),
  setEmpresaId: (id) => localStorage.setItem('pf_empresa_id', id),
};

// ─── HTTP ────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const token = Auth.getToken();
  const res = await fetch(API_URL + path, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    },
    ...opts,
  });

  if (res.status === 401) {
    Auth.clear();
    window.location.href = 'login.html';
    return;
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Erro ${res.status}`);
  return data;
}

// ─── AUTH API ────────────────────────────────────────────
const AuthAPI = {
  async login(email, senha) {
    const data = await apiFetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, senha }),
    });
    Auth.setToken(data.token);
    Auth.setUser(data.user);
    // Seleciona automaticamente a primeira empresa do usuário
    if (data.user.empresas?.length === 1) {
      Auth.setEmpresaId(data.user.empresas[0]);
    }
    return data;
  },

  async me() {
    return apiFetch('/auth/me');
  },

  logout() {
    Auth.clear();
    window.location.href = 'login.html';
  }
};

// ─── EMPRESAS API ────────────────────────────────────────
const EmpresasAPI = {
  list:   ()     => apiFetch('/empresas'),
  get:    (id)   => apiFetch(`/empresas/${id}`),
  create: (data) => apiFetch('/empresas', { method: 'POST', body: JSON.stringify(data) }),
  update: (id, data) => apiFetch(`/empresas/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  delete: (id)   => apiFetch(`/empresas/${id}`, { method: 'DELETE' }),
};

// ─── TRANSAÇÕES API ──────────────────────────────────────
const TransacoesAPI = {
  get: (empresaId) => apiFetch(`/empresas/${empresaId}/transacoes`),

  /** Envia as transações processadas pelo parser do frontend para o banco */
  save: (empresaId, transacoes) => apiFetch(`/empresas/${empresaId}/transacoes`, {
    method: 'POST',
    body: JSON.stringify({ transacoes }),
  }),
};

// ─── MAPEAMENTOS API ─────────────────────────────────────
const MapeamentosAPI = {
  get: (empresaId) => apiFetch(`/empresas/${empresaId}/mapeamentos`),

  save: (empresaId, mapeamentos) => apiFetch(`/empresas/${empresaId}/mapeamentos`, {
    method: 'POST',
    body: JSON.stringify(mapeamentos),
  }),
};

// ─── USUÁRIOS API ────────────────────────────────────────
const UsuariosAPI = {
  list:   ()       => apiFetch('/usuarios'),
  create: (data)   => apiFetch('/usuarios', { method: 'POST', body: JSON.stringify(data) }),
  update: (id, d)  => apiFetch(`/usuarios/${id}`, { method: 'PUT', body: JSON.stringify(d) }),
  delete: (id)     => apiFetch(`/usuarios/${id}`, { method: 'DELETE' }),
  resetSenha: (id, senha) => apiFetch(`/usuarios/${id}/reset-senha`, {
    method: 'POST', body: JSON.stringify({ senha })
  }),
};

// ─── GUARD — redireciona para login se não autenticado ───
function requireLogin() {
  if (!Auth.getToken()) {
    window.location.href = 'login.html';
    return false;
  }
  return true;
}

// ─── GUARD — apenas admin ────────────────────────────────
function requireAdmin() {
  if (!requireLogin()) return false;
  if (!Auth.isAdmin()) {
    window.location.href = 'finreport.html';
    return false;
  }
  return true;
}

// ─── SIDEBAR — preenche nome do usuário ──────────────────
function initSidebarUser() {
  const user = Auth.getUser();
  if (!user) return;
  const nameEl = document.getElementById('sb-user-name');
  const roleEl = document.getElementById('sb-user-role');
  const avEl   = document.getElementById('sb-user-avatar');
  if (nameEl) nameEl.textContent = user.nome + ' ' + (user.sobrenome || '');
  if (roleEl) roleEl.textContent = user.role === 'admin' ? 'Administrador' : 'Cliente';
  if (avEl)   avEl.textContent   = (user.nome[0] + (user.sobrenome?.[0] || '')).toUpperCase();
}

// Expõe globalmente
window.Auth        = Auth;
window.AuthAPI     = AuthAPI;
window.EmpresasAPI = EmpresasAPI;
window.TransacoesAPI = TransacoesAPI;
window.MapeamentosAPI = MapeamentosAPI;
window.UsuariosAPI = UsuariosAPI;
window.requireLogin  = requireLogin;
window.requireAdmin  = requireAdmin;
window.initSidebarUser = initSidebarUser;
