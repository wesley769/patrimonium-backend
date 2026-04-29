from flask import Flask, request, jsonify, g
from flask_cors import CORS
import psycopg
from psycopg.rows import dict_row
import bcrypt
import jwt
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
import json
import re

app = Flask(__name__)

ALLOWED_ORIGINS = [
    "https://patrimonium-finance.vercel.app",
    "https://patrimonium-finance-git-main-wesley-1800s-projects.vercel.app",
    "https://patrimonium-finance-bk087cjiv-wesley-1800s-projects.vercel.app",
    "http://localhost:8080",
    "http://localhost:5500",
]

@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin","")
    if origin in ALLOWED_ORIGINS or "patrimonium-finance" in origin:
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"]     = "GET,POST,PUT,DELETE,OPTIONS"
        response.headers["Access-Control-Allow-Headers"]     = "Content-Type,Authorization"
    return response

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        origin = request.headers.get("Origin","")
        from flask import Response
        resp = Response()
        if origin in ALLOWED_ORIGINS or "patrimonium-finance" in origin:
            resp.headers["Access-Control-Allow-Origin"]      = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Methods"]     = "GET,POST,PUT,DELETE,OPTIONS"
            resp.headers["Access-Control-Allow-Headers"]     = "Content-Type,Authorization"
        return resp, 200

CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}}, supports_credentials=True)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET   = os.environ.get("JWT_SECRET", "patrimonium-dev-secret-2026")
JWT_EXP_H    = int(os.environ.get("JWT_EXP_H", "8"))

# ─── DB ──────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

# ─── AUTH HELPERS ────────────────────────────────────────
def make_token(user_id, role, empresa_ids):
    payload = {
        "sub":        str(user_id),
        "role":       role,
        "empresas":   empresa_ids,
        "exp":        datetime.now(timezone.utc) + timedelta(hours=JWT_EXP_H),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify(error="Token ausente"), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            g.user_id  = payload["sub"]
            g.role     = payload["role"]
            g.empresas = payload.get("empresas", [])
        except jwt.ExpiredSignatureError:
            return jsonify(error="Token expirado"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="Token inválido"), 401
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.role != "admin":
            return jsonify(error="Acesso restrito"), 403
        return f(*args, **kwargs)
    return decorated

def can_access_empresa(empresa_id):
    if g.role == "admin":
        return True
    return str(empresa_id) in [str(e) for e in g.empresas]

@app.errorhandler(500)
def handle_500(e):
    origin = request.headers.get("Origin","")
    resp = jsonify(error=str(e))
    resp.status_code = 500
    if "patrimonium-finance" in origin:
        resp.headers["Access-Control-Allow-Origin"]      = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    app.logger.error(f"Unhandled exception: {traceback.format_exc()}")
    origin = request.headers.get("Origin","")
    resp = jsonify(error=str(e), trace=traceback.format_exc())
    resp.status_code = 500
    if "patrimonium-finance" in origin:
        resp.headers["Access-Control-Allow-Origin"]      = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

# ─── HEALTH ──────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify(status="ok", version="1.0.0")

# ─── AUTH ────────────────────────────────────────────────
@app.route("/auth/login", methods=["POST"])
def login():
    data  = request.get_json()
    email = (data.get("email") or "").strip().lower()
    senha = (data.get("senha") or "")
    if not email or not senha:
        return jsonify(error="E-mail e senha obrigatórios"), 400

    db  = get_db()
    cur = db.execute(
        "SELECT id, nome, sobrenome, email, senha_hash, role FROM usuarios WHERE email=%s AND ativo=true",
        (email,)
    )
    user = cur.fetchone()
    if not user or not bcrypt.checkpw(senha.encode(), user["senha_hash"].encode()):
        return jsonify(error="Credenciais inválidas"), 401

    # Busca empresas do usuário
    cur2 = db.execute(
        "SELECT empresa_id FROM usuario_empresas WHERE usuario_id=%s",
        (user["id"],)
    )
    empresa_ids = [str(r["empresa_id"]) for r in cur2.fetchall()]

    token = make_token(user["id"], user["role"], empresa_ids)
    return jsonify(
        token=token,
        user=dict(
            id=str(user["id"]), nome=user["nome"],
            sobrenome=user["sobrenome"], email=user["email"],
            role=user["role"], empresas=empresa_ids
        )
    )

@app.route("/auth/me")
@require_auth
def me():
    db  = get_db()
    cur = db.execute(
        "SELECT id, nome, sobrenome, email, role FROM usuarios WHERE id=%s",
        (g.user_id,)
    )
    user = cur.fetchone()
    if not user:
        return jsonify(error="Usuário não encontrado"), 404
    u2=dict(user);u2["id"]=str(u2["id"]);u2["empresas"]=g.empresas;return jsonify(user=u2)

# ─── EMPRESAS ────────────────────────────────────────────
@app.route("/empresas", methods=["GET"])
@require_auth
def list_empresas():
    db = get_db()
    if g.role == "admin":
        rows = db.execute("SELECT * FROM empresas ORDER BY razao").fetchall()
    else:
        rows = db.execute(
            "SELECT e.* FROM empresas e JOIN usuario_empresas ue ON ue.empresa_id=e.id WHERE ue.usuario_id=%s ORDER BY e.razao",
            (g.user_id,)
        ).fetchall()
    def _fix(r): d=dict(r);d["id"]=str(d["id"]);return d
    return jsonify(empresas=[_fix(r) for r in rows])

@app.route("/empresas", methods=["POST"])
@require_auth
@require_admin
def create_empresa():
    d  = request.get_json()
    db = get_db()
    cur = db.execute(
        """INSERT INTO empresas (razao, fantasia, cnpj, segmento, regime, porte, cidade, estado, cor, status)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
        (d.get("razao"), d.get("fantasia"), d.get("cnpj"), d.get("segmento"),
         d.get("regime"), d.get("porte"), d.get("cidade"), d.get("estado"),
         d.get("cor","#2563eb"), d.get("status","Ativa"))
    )
    db.commit()
    row = cur.fetchone()
    result = dict(row)
    result['id'] = str(result['id'])
    return jsonify(empresa=result), 201

@app.route("/empresas/<empresa_id>", methods=["GET"])
@require_auth
def get_empresa(empresa_id):
    if not can_access_empresa(empresa_id):
        return jsonify(error="Sem acesso"), 403
    db  = get_db()
    row = db.execute("SELECT * FROM empresas WHERE id=%s", (empresa_id,)).fetchone()
    if not row: return jsonify(error="Empresa não encontrada"), 404
    result = dict(row)
    result['id'] = str(result['id'])
    return jsonify(empresa=result)

@app.route("/empresas/<empresa_id>", methods=["PUT"])
@require_auth
@require_admin
def update_empresa(empresa_id):
    d  = request.get_json()
    db = get_db()
    db.execute(
        """UPDATE empresas SET razao=%s,fantasia=%s,cnpj=%s,segmento=%s,regime=%s,
           porte=%s,cidade=%s,estado=%s,cor=%s,status=%s WHERE id=%s""",
        (d.get("razao"), d.get("fantasia"), d.get("cnpj"), d.get("segmento"),
         d.get("regime"), d.get("porte"), d.get("cidade"), d.get("estado"),
         d.get("cor"), d.get("status"), empresa_id)
    )
    db.commit()
    return jsonify(ok=True)

@app.route("/empresas/<empresa_id>", methods=["DELETE"])
@require_auth
@require_admin
def delete_empresa(empresa_id):
    db = get_db()
    db.execute("DELETE FROM empresas WHERE id=%s", (empresa_id,))
    db.commit()
    return jsonify(ok=True)

# ─── TRANSAÇÕES ──────────────────────────────────────────
@app.route("/empresas/<empresa_id>/transacoes", methods=["GET"])
@require_auth
def get_transacoes(empresa_id):
    if not can_access_empresa(empresa_id):
        return jsonify(error="Sem acesso"), 403
    db   = get_db()
    rows = db.execute(
        "SELECT * FROM transacoes WHERE empresa_id=%s ORDER BY data_competencia",
        (empresa_id,)
    ).fetchall()
    def _fixt(r): d=dict(r);d["id"]=str(d["id"]);return d
    return jsonify(transacoes=[_fixt(r) for r in rows])

@app.route("/empresas/<empresa_id>/transacoes", methods=["POST"])
@require_auth
@require_admin
def save_transacoes(empresa_id):
    data = request.get_json()
    txs  = data.get("transacoes", [])
    if not txs:
        return jsonify(error="Nenhuma transação enviada"), 400

    db = get_db()
    # Só limpa se for o primeiro lote (append=False ou ausente)
    append = data.get("append", False)
    if not append:
        db.execute("DELETE FROM transacoes WHERE empresa_id=%s", (empresa_id,))

    # Bulk insert com executemany
    rows = []
    for t in txs:
        rows.append((
            empresa_id,
            _parse_date(t.get("dataCompetencia")),
            _parse_date(t.get("dataPagamento")),
            _parse_date(t.get("dataMovimento")),
            (t.get("nomeContraparte") or "")[:500],
            (t.get("descricao") or "")[:500],
            (t.get("contaBancaria") or "")[:200],
            (t.get("situacao") or "")[:100],
            float(t.get("valorTotal") or 0),
            json.dumps(t.get("cats", []), ensure_ascii=False),
        ))

    if not rows:
        return jsonify(ok=True, count=0)

    sql = """INSERT INTO transacoes
           (empresa_id,data_competencia,data_pagamento,data_movimento,
            nome_contraparte,descricao,conta_bancaria,situacao,valor_total,cats_json)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    with db.cursor() as cur:
        cur.executemany(sql, rows)
    db.commit()
    return jsonify(ok=True, count=len(rows))

def _parse_date(v):
    if not v: return None
    if isinstance(v, str):
        try:
            # Remove timezone info and parse
            v2 = v.replace("Z","").replace("+00:00","").split(".")[0]
            return datetime.fromisoformat(v2).date()
        except:
            try: return datetime.strptime(v[:10], "%Y-%m-%d").date()
            except: return None
    if isinstance(v, (int, float)):
        try: return datetime.fromtimestamp(v/1000).date()
        except: return None
    return None

# ─── MAPEAMENTOS ─────────────────────────────────────────
@app.route("/empresas/<empresa_id>/mapeamentos", methods=["GET"])
@require_auth
def get_mapeamentos(empresa_id):
    if not can_access_empresa(empresa_id):
        return jsonify(error="Sem acesso"), 403
    db  = get_db()
    row = db.execute(
        "SELECT * FROM mapeamentos WHERE empresa_id=%s ORDER BY atualizado_em DESC LIMIT 1",
        (empresa_id,)
    ).fetchone()
    if not row:
        return jsonify(mapeamentos=None)
    return jsonify(mapeamentos=dict(
        column_map   = row["column_map_json"],
        category_map = row["category_map_json"],
        plano_contas = row["plano_contas_json"],
        balanco_manual = row["balanco_manual_json"],
        balanco_corte  = row["balanco_corte_json"],
        atualizado_em  = row["atualizado_em"].isoformat() if row["atualizado_em"] else None
    ))

@app.route("/empresas/<empresa_id>/mapeamentos", methods=["POST"])
@require_auth
@require_admin
def save_mapeamentos(empresa_id):
    d  = request.get_json()
    db = get_db()
    # Upsert
    db.execute(
        """INSERT INTO mapeamentos
           (empresa_id, column_map_json, category_map_json, plano_contas_json,
            balanco_manual_json, balanco_corte_json, atualizado_em)
           VALUES (%s,%s,%s,%s,%s,%s,NOW())
           ON CONFLICT (empresa_id) DO UPDATE SET
           column_map_json=%s, category_map_json=%s, plano_contas_json=%s,
           balanco_manual_json=%s, balanco_corte_json=%s, atualizado_em=NOW()""",
        (
            empresa_id,
            json.dumps(d.get("column_map",   {})),
            json.dumps(d.get("category_map", {})),
            json.dumps(d.get("plano_contas", [])),
            json.dumps(d.get("balanco_manual", {})),
            json.dumps(d.get("balanco_corte",  {})),
            json.dumps(d.get("column_map",   {})),
            json.dumps(d.get("category_map", {})),
            json.dumps(d.get("plano_contas", [])),
            json.dumps(d.get("balanco_manual", {})),
            json.dumps(d.get("balanco_corte",  {})),
        )
    )
    db.commit()
    return jsonify(ok=True)

# ─── USUÁRIOS ────────────────────────────────────────────
@app.route("/usuarios", methods=["GET"])
@require_auth
@require_admin
def list_usuarios():
    db   = get_db()
    rows = db.execute(
        "SELECT id,nome,sobrenome,email,role,ativo,criado_em FROM usuarios ORDER BY nome"
    ).fetchall()
    result = []
    for r in rows:
        cur2 = db.execute("SELECT empresa_id FROM usuario_empresas WHERE usuario_id=%s", (r["id"],))
        emps = [str(x["empresa_id"]) for x in cur2.fetchall()]
        rr=dict(r);rr["id"]=str(rr["id"]);rr["empresas"]=emps;
        rr["criado_em"]=r["criado_em"].isoformat() if r["criado_em"] else None
        result.append(rr)
    return jsonify(usuarios=result)

@app.route("/usuarios", methods=["POST"])
@require_auth
@require_admin
def create_usuario():
    d     = request.get_json()
    email = (d.get("email") or "").strip().lower()
    senha = d.get("senha") or "Patrimonium@2026"
    nome  = d.get("nome","")
    role  = d.get("role","cliente")
    emps  = d.get("empresas", [])

    if not email or not nome:
        return jsonify(error="Nome e e-mail obrigatórios"), 400

    db = get_db()
    if db.execute("SELECT id FROM usuarios WHERE email=%s", (email,)).fetchone():
        return jsonify(error="E-mail já cadastrado"), 409

    hashed = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()
    cur = db.execute(
        "INSERT INTO usuarios (nome,sobrenome,email,senha_hash,role,ativo) VALUES (%s,%s,%s,%s,%s,true) RETURNING id",
        (nome, d.get("sobrenome",""), email, hashed, role)
    )
    user_id = cur.fetchone()["id"]

    for emp in emps:
        # emps pode ser lista de objetos {id, role} ou lista de strings
        if isinstance(emp, dict):
            emp_id   = emp.get("id") or emp.get("empresa_id")
            emp_role = emp.get("role","cliente")
        else:
            emp_id   = emp
            emp_role = d.get("role_empresa","cliente")
        if emp_id:
            db.execute(
                "INSERT INTO usuario_empresas (usuario_id,empresa_id,role) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                (user_id, str(emp_id), emp_role)
            )
    db.commit()
    return jsonify(ok=True, id=str(user_id)), 201

@app.route("/usuarios/<usuario_id>", methods=["PUT"])
@require_auth
@require_admin
def update_usuario(usuario_id):
    d  = request.get_json()
    db = get_db()
    db.execute(
        "UPDATE usuarios SET nome=%s,sobrenome=%s,role=%s,ativo=%s WHERE id=%s",
        (d.get("nome"), d.get("sobrenome"), d.get("role"), d.get("ativo",True), usuario_id)
    )
    if d.get("empresas") is not None:
        db.execute("DELETE FROM usuario_empresas WHERE usuario_id=%s", (usuario_id,))
        for emp in d["empresas"]:
            if isinstance(emp, dict):
                emp_id   = emp.get("id") or emp.get("empresa_id")
                emp_role = emp.get("role","cliente")
            else:
                emp_id   = emp
                emp_role = d.get("role_empresa","cliente")
            if emp_id:
                db.execute(
                    "INSERT INTO usuario_empresas (usuario_id,empresa_id,role) VALUES (%s,%s,%s)",
                    (usuario_id, str(emp_id), emp_role)
                )
    if d.get("nova_senha"):
        hashed = bcrypt.hashpw(d["nova_senha"].encode(), bcrypt.gensalt()).decode()
        db.execute("UPDATE usuarios SET senha_hash=%s WHERE id=%s", (hashed, usuario_id))
    db.commit()
    return jsonify(ok=True)

@app.route("/usuarios/<usuario_id>", methods=["DELETE"])
@require_auth
@require_admin
def delete_usuario(usuario_id):
    db = get_db()
    db.execute("DELETE FROM usuarios WHERE id=%s", (usuario_id,))
    db.commit()
    return jsonify(ok=True)

@app.route("/usuarios/<usuario_id>/reset-senha", methods=["POST"])
@require_auth
@require_admin
def reset_senha(usuario_id):
    nova = request.get_json().get("senha","Patrimonium@2026")
    db   = get_db()
    hashed = bcrypt.hashpw(nova.encode(), bcrypt.gensalt()).decode()
    db.execute("UPDATE usuarios SET senha_hash=%s WHERE id=%s", (hashed, usuario_id))
    db.commit()
    return jsonify(ok=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
