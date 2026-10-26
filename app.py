import hashlib
import hmac
import html
import os
import secrets
import sqlite3
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("HOST", "0.0.0.0")
PORTA = int(os.environ.get("PORT", "8000"))
BANCO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cnpj_finder.db")
MAX_GERACAO = 500

# ------------------------------------------------------------ DDD
# Telefone sem símbolos, para extrair o DDD direto no SQL.
_TEL_LIMPO = (
    "REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE("
    "COALESCE(e.telefone,''),'(',''),')',''),' ',''),'-',''),'+',''),'.','')"
)
# Trata "+55 11 ...", "011 ..." e "11 ...".
SQL_DDD = (
    f"(CASE "
    f"WHEN {_TEL_LIMPO} LIKE '55%' AND LENGTH({_TEL_LIMPO}) >= 12 "
    f"THEN SUBSTR({_TEL_LIMPO},3,2) "
    f"WHEN {_TEL_LIMPO} LIKE '0%' THEN SUBSTR({_TEL_LIMPO},2,2) "
    f"ELSE SUBSTR({_TEL_LIMPO},1,2) END)"
)


def extrair_ddd(telefone):
    """Mesma regra do SQL_DDD, para mostrar o DDD na tabela."""
    n = "".join(ch for ch in str(telefone or "") if ch.isdigit())
    if n.startswith("55") and len(n) >= 12:
        return n[2:4]
    if n.startswith("0"):
        return n[1:3]
    return n[:2]


def normalizar_ddd(valor):
    """Retorna só os 2 dígitos do DDD, ou '' se for inválido/vazio."""
    digitos = "".join(ch for ch in str(valor or "") if ch.isdigit())
    return digitos[-2:] if len(digitos) >= 2 else ""


def tem_coluna_ramo(con):
    return any(l["name"].lower() == "ramo"
               for l in con.execute("PRAGMA table_info(empresas)"))


def listar_ramos():
    """Lê a lista de ramos criada pelo classificar_ramos.py."""
    con = conectar()
    try:
        return con.execute(
            "SELECT ramo, total FROM ramos_disponiveis ORDER BY ramo"
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        con.close()


# ---------------------------------------------------------------- AUTENTICAÇÃO
# Defina SECRET_KEY como variável de ambiente na hospedagem (texto longo e
# aleatório). Se não definir, uma chave temporária é criada a cada execução
# (funciona, mas todo mundo precisa logar de novo quando o servidor reinicia).
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
COOKIE_SEGURO = os.environ.get("COOKIE_SECURE") == "1"  # use 1 quando estiver em HTTPS
SESSAO_SEGUNDOS = 60 * 60 * 24 * 7  # 7 dias
NOME_COOKIE = "sessao"


def assinar(texto):
    return hmac.new(SECRET_KEY.encode(), texto.encode(), hashlib.sha256).hexdigest()


def criar_token(email):
    expira = int(time.time()) + SESSAO_SEGUNDOS
    texto = f"{email.encode().hex()}.{expira}"
    return f"{texto}.{assinar(texto)}"


def ler_token(valor):
    """Retorna o e-mail se o token for válido e não expirado; senão None."""
    try:
        email_hex, expira, assinatura = valor.split(".")
        texto = f"{email_hex}.{expira}"
        if not hmac.compare_digest(assinatura, assinar(texto)):
            return None
        if int(expira) < time.time():
            return None
        return bytes.fromhex(email_hex).decode()
    except Exception:
        return None


def gerar_hash(senha, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${h}"


def conferir_senha(senha, armazenado):
    try:
        salt, _ = armazenado.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(gerar_hash(senha, salt), armazenado)


def criar_usuario(email, senha):
    """Retorna True se criou, False se o e-mail já existe."""
    con = conectar()
    try:
        con.execute(
            "INSERT INTO usuarios (email, senha_hash) VALUES (?, ?)",
            (email, gerar_hash(senha)),
        )
        con.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        con.close()


def login_valido(email, senha):
    con = conectar()
    try:
        linha = con.execute(
            "SELECT senha_hash FROM usuarios WHERE email = ?", (email,)
        ).fetchone()
    finally:
        con.close()
    return bool(linha) and conferir_senha(senha, linha["senha_hash"])


# ----------------------------------------------------------------------- BANCO
def conectar():
    con = sqlite3.connect(BANCO, timeout=30)
    con.row_factory = sqlite3.Row
    return con


def preparar_banco():
    """Cria as tabelas auxiliares (CNPJs usados e usuários)."""
    con = conectar()
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS empresas_geradas (
                cnpj TEXT PRIMARY KEY,
                data_geracao TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_empresas_geradas_data
            ON empresas_geradas(data_geracao)
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                senha_hash TEXT NOT NULL,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        con.commit()
    finally:
        con.close()


def contar_disponiveis():
    con = conectar()
    try:
        total = con.execute("""
            SELECT COUNT(*)
            FROM empresas e
            WHERE e.cnpj IS NOT NULL
              AND TRIM(e.cnpj) != ''
              AND NOT EXISTS (
                  SELECT 1 FROM empresas_geradas g
                  WHERE g.cnpj = e.cnpj
              )
        """).fetchone()[0]
        return total
    finally:
        con.close()


def contar_geradas():
    con = conectar()
    try:
        return con.execute(
            "SELECT COUNT(*) FROM empresas_geradas"
        ).fetchone()[0]
    finally:
        con.close()


def buscar_empresas(termo, ddd="", ramo="", quantidade=100):
    """Busca empresas ainda não usadas (por texto e/ou DDD) e registra os resultados."""
    termo = termo.strip()
    ddd = normalizar_ddd(ddd)
    ramo = ramo.strip()
    quantidade = max(1, min(int(quantidade), MAX_GERACAO))
    if not termo and not ddd and not ramo:
        return []

    filtros = []
    params = []
    if termo:
        filtros.append("(e.nome LIKE ? OR e.cnpj LIKE ? OR e.telefone LIKE ?)")
        padrao = f"%{termo}%"
        params += [padrao, padrao, padrao]
    if ddd:
        filtros.append(f"{SQL_DDD} = ?")
        params.append(ddd)

    con = conectar()
    try:
        if ramo:
            if not tem_coluna_ramo(con):
                raise ValueError("Rode o classificar_ramos.py antes de filtrar por ramo.")
            filtros.append("e.ramo = ?")
            params.append(ramo)
        ramo_sql = "e.ramo" if tem_coluna_ramo(con) else "NULL"
        con.execute("BEGIN IMMEDIATE")
        resultados = con.execute(f"""
            SELECT e.cnpj, e.nome, e.telefone, {ramo_sql} AS ramo
            FROM empresas e
            WHERE {' AND '.join(filtros)}
              AND e.cnpj IS NOT NULL
              AND TRIM(e.cnpj) != ''
              AND NOT EXISTS (
                  SELECT 1
                  FROM empresas_geradas g
                  WHERE g.cnpj = e.cnpj
              )
            ORDER BY e.nome
            LIMIT ?
        """, params + [quantidade]).fetchall()

        # Registra todos os resultados mostrados para que não apareçam
        # novamente em buscas futuras nem na geração aleatória.
        if resultados:
            con.executemany("""
                INSERT OR IGNORE INTO empresas_geradas (cnpj)
                VALUES (?)
            """, [(empresa["cnpj"],) for empresa in resultados])
        con.commit()
        return resultados
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def gerar_empresas(quantidade, ddd="", ramo=""):
    """Seleciona CNPJs aleatórios ainda não usados (opcionalmente de um DDD)."""
    quantidade = max(1, min(int(quantidade), MAX_GERACAO))
    ddd = normalizar_ddd(ddd)

    filtro_ddd = ""
    params = []
    if ddd:
        filtro_ddd = f"AND {SQL_DDD} = ?"
        params.append(ddd)
    ramo = ramo.strip()

    con = conectar()
    try:
        filtro_ramo = ""
        if ramo:
            if not tem_coluna_ramo(con):
                raise ValueError("Rode o classificar_ramos.py antes de filtrar por ramo.")
            filtro_ramo = "AND e.ramo = ?"
            params.append(ramo)
        params.append(quantidade)
        ramo_sql = "e.ramo" if tem_coluna_ramo(con) else "NULL"
        con.execute("BEGIN IMMEDIATE")
        resultados = con.execute(f"""
            SELECT e.cnpj, e.nome, e.telefone, {ramo_sql} AS ramo
            FROM empresas e
            WHERE e.cnpj IS NOT NULL
              AND TRIM(e.cnpj) != ''
              {filtro_ddd}
              {filtro_ramo}
              AND NOT EXISTS (
                  SELECT 1
                  FROM empresas_geradas g
                  WHERE g.cnpj = e.cnpj
              )
            ORDER BY RANDOM()
            LIMIT ?
        """, params).fetchall()

        if resultados:
            con.executemany("""
                INSERT OR IGNORE INTO empresas_geradas (cnpj)
                VALUES (?)
            """, [(empresa["cnpj"],) for empresa in resultados])
        con.commit()
        return resultados
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


# ------------------------------------------------------------------- PÁGINAS
def escapar(valor):
    return html.escape(str(valor or ""))


def tabela_empresas(empresas):
    if not empresas:
        return """
        <div class="vazio">
            Nenhuma empresa disponível encontrada.
            Talvez os resultados já tenham sido usados.
        </div>
        """

    linhas = []
    for empresa in empresas:
        linhas.append(f"""
        <tr>
            <td>{escapar(empresa['cnpj'])}</td>
            <td>{escapar(empresa['nome'])}</td>
            <td>{escapar(empresa['telefone'])}</td>
            <td>{escapar(extrair_ddd(empresa['telefone']) or '—')}</td>
            <td>{escapar(empresa['ramo'] or '—')}</td>
        </tr>
        """)

    return f"""
    <div class="tabela-wrap">
        <table>
            <thead>
                <tr><th>CNPJ</th><th>Nome fantasia</th><th>Telefone</th>
                <th>DDD</th><th>Ramo</th></tr>
            </thead>
            <tbody>{''.join(linhas)}</tbody>
        </table>
    </div>
    """


def pagina_auth(titulo, acao, erro="", link=""):
    """Tela de login/cadastro, no mesmo visual escuro do site."""
    msg = f'<div class="erro">{escapar(erro)}</div>' if erro else ""
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escapar(titulo)} - Extrator Bessa</title>
<style>
:root {{
  color-scheme: dark;
  --fundo: #0b1220; --cartao: #121c2e; --borda: #26364e;
  --texto: #edf3fb; --suave: #9eafc5; --azul: #42a5f5;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; background: var(--fundo); color: var(--texto);
  font: 16px/1.5 Arial, Helvetica, sans-serif;
  display: flex; justify-content: center; padding: 60px 16px;
}}
.caixa {{
  background: var(--cartao); border: 1px solid var(--borda);
  border-radius: 14px; padding: 28px; width: 100%; max-width: 380px;
}}
h1 {{ margin: 0 0 4px; font-size: 28px; }}
h2 {{ margin: 0 0 16px; font-size: 20px; color: var(--suave); font-weight: 400; }}
label {{ display: block; margin: 12px 0 6px; color: var(--suave); }}
input, button {{ font: inherit; border-radius: 8px; padding: 11px 12px; width: 100%; }}
input {{ background: #0b1424; border: 1px solid var(--borda); color: var(--texto); }}
button {{
  border: 0; background: var(--azul); color: #061321;
  font-weight: 700; cursor: pointer; margin-top: 18px;
}}
button:hover {{ filter: brightness(1.08); }}
.erro {{ background: #3a1a22; color: #ffb4b4; padding: 10px 12px; border-radius: 8px; margin-bottom: 8px; }}
.link {{ color: var(--suave); margin: 18px 0 0; text-align: center; }}
a {{ color: var(--azul); }}
</style>
</head>
<body>
<div class="caixa">
  <h1>Extrator Bessa</h1>
  <h2>{escapar(titulo)}</h2>
  {msg}
  <form method="post" action="{acao}">
    <label for="email">E-mail</label>
    <input id="email" name="email" type="email" maxlength="200" required autofocus>
    <label for="senha">Senha</label>
    <input id="senha" name="senha" type="password" minlength="6" maxlength="200" required>
    <button type="submit">{escapar(titulo)}</button>
  </form>
  <p class="link">{link}</p>
</div>
</body>
</html>"""


def pagina(conteudo="", titulo="CNPJ Finder", aviso="", usuario=""):
    disponiveis = contar_disponiveis()
    usados = contar_geradas()
    opcoes_ramo = "".join(
        f'<option value="{escapar(r["ramo"])}">{escapar(r["ramo"])} ({r["total"]:,})</option>'
        for r in listar_ramos()
    )
    aviso_html = f'<div class="aviso">{escapar(aviso)}</div>' if aviso else ""
    sair_html = (
        f'<a href="/logout">Sair ({escapar(usuario)})</a>' if usuario else ""
    )
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escapar(titulo).replace('CNPJ Finder', 'Extrator Bessa')}</title>
<style>
:root {{
  color-scheme: dark;
  --fundo: #0b1220;
  --cartao: #121c2e;
  --borda: #26364e;
  --texto: #edf3fb;
  --suave: #9eafc5;
  --azul: #42a5f5;
  --verde: #38c793;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; background: var(--fundo); color: var(--texto);
  font: 16px/1.5 Arial, Helvetica, sans-serif;
}}
main {{ width: min(1100px, 94%); margin: 36px auto; }}
header {{ margin-bottom: 24px; }}
h1 {{ margin: 0 0 6px; font-size: clamp(28px, 5vw, 40px); }}
.subtitulo {{ color: var(--suave); margin: 0; }}
.stats {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 14px; margin: 22px 0;
}}
.card, .painel {{
  background: var(--cartao); border: 1px solid var(--borda);
  border-radius: 14px; padding: 20px;
}}
.stat-label {{ color: var(--suave); font-size: 14px; }}
.stat-numero {{ font-size: 28px; font-weight: 700; margin-top: 4px; }}
.paineis {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px; margin: 20px 0;
}}
h2 {{ margin: 0 0 12px; font-size: 21px; }}
label {{ display: block; margin: 12px 0 6px; color: var(--suave); }}
input, select, button {{
  font: inherit; border-radius: 8px; padding: 11px 12px;
}}
input, select {{
  width: 100%; background: #0b1424; border: 1px solid var(--borda);
  color: var(--texto);
}}
button, .botao {{
  border: 0; background: var(--azul); color: #061321;
  font-weight: 700; cursor: pointer; text-decoration: none;
  display: inline-block; margin-top: 12px;
}}
button:hover, .botao:hover {{ filter: brightness(1.08); }}
.links {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 0; }}
.links a {{
  color: var(--texto); border: 1px solid var(--borda);
  border-radius: 8px; padding: 8px 12px; text-decoration: none;
}}
.resultados {{ margin-top: 24px; }}
.tabela-wrap {{ overflow-x: auto; border: 1px solid var(--borda); border-radius: 10px; }}
table {{ width: 100%; border-collapse: collapse; min-width: 820px; }}
th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid var(--borda); }}
th {{ background: #1a2940; }}
tr:last-child td {{ border-bottom: 0; }}
.vazio, .aviso {{
  padding: 14px; border-radius: 9px; margin: 14px 0;
  background: #1a2940; color: var(--suave);
}}
.rodape {{ color: var(--suave); font-size: 13px; margin-top: 28px; }}
@media (max-width: 500px) {{
  main {{ margin: 20px auto; }}
  .card, .painel {{ padding: 15px; }}
}}
</style>
</head>
<body>
<main>
  <header>
    <h1>Extrator Bessa</h1>
    <p class="subtitulo">Pesquisa local e seleção aleatória de empresas da sua base SQLite.</p>
  </header>

  {aviso_html}

  <section class="stats">
    <div class="card">
      <div class="stat-label">CNPJs disponíveis</div>
      <div class="stat-numero">{disponiveis:,}</div>
    </div>
    <div class="card">
      <div class="stat-label">CNPJs já utilizados</div>
      <div class="stat-numero">{usados:,}</div>
    </div>
  </section>

  <section class="paineis">
    <div class="painel">
      <h2>Buscar empresas</h2>
      <p class="subtitulo">Os resultados exibidos ficam registrados e não voltam a aparecer.</p>
      <form method="get" action="/buscar">
        <label for="q">Nome, CNPJ ou telefone (opcional se informar o DDD)</label>
        <input id="q" name="q" type="text" maxlength="120"
               placeholder="Ex.: nome da empresa ou número">
        <label for="ddd_busca">DDD (opcional)</label>
        <input id="ddd_busca" name="ddd" type="text" inputmode="numeric"
               maxlength="3" placeholder="Ex.: 11">
        <label for="ramo_busca">Ramo (opcional)</label>
        <select id="ramo_busca" name="ramo">
          <option value="">Todos</option>{opcoes_ramo}
        </select>
        <label for="quantidade_busca">Quantidade de empresas</label>
        <select id="quantidade_busca" name="quantidade">
          <option value="10">10 empresas</option>
          <option value="50">50 empresas</option>
          <option value="100" selected>100 empresas</option>
          <option value="250">250 empresas</option>
          <option value="500">500 empresas</option>
        </select>
        <button type="submit">Buscar</button>
      </form>
    </div>

    <div class="painel">
      <h2>Gerar CNPJs aleatórios</h2>
      <p class="subtitulo">Cada CNPJ é usado uma única vez entre buscas e gerações.</p>
      <form method="post" action="/gerar">
        <label for="quantidade">Quantidade</label>
        <select id="quantidade" name="quantidade">
          <option value="10">10 empresas</option>
          <option value="50">50 empresas</option>
          <option value="100">100 empresas</option>
          <option value="250">250 empresas</option>
          <option value="500">500 empresas</option>
        </select>
        <label for="ddd_gerar">DDD (opcional, vazio = todos)</label>
        <input id="ddd_gerar" name="ddd" type="text" inputmode="numeric"
               maxlength="3" placeholder="Ex.: 11">
        <label for="ramo_gerar">Ramo (opcional)</label>
        <select id="ramo_gerar" name="ramo">
          <option value="">Todos</option>{opcoes_ramo}
        </select>
        <button type="submit">Gerar empresas</button>
      </form>
    </div>
  </section>

  <nav class="links">
    <a href="/">Início</a>
    <a href="/historico">Histórico de CNPJs utilizados</a>
    {sair_html}
  </nav>

  <section class="resultados">
    <h2>{escapar(titulo)}</h2>
    {conteudo}
  </section>

  <p class="rodape">
    Uso local para estudo e testes. Os dados empresariais devem ser tratados
    conforme a legislação aplicável. A busca registra os resultados apresentados.
  </p>
</main>
</body>
</html>"""


# -------------------------------------------------------------------- SERVIDOR
class CNPJHandler(BaseHTTPRequestHandler):
    usuario = ""

    def responder(self, status, corpo, cabecalhos=None):
        dados = corpo.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(dados)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for nome, valor in (cabecalhos or []):
            self.send_header(nome, valor)
        self.end_headers()
        self.wfile.write(dados)

    def redirecionar(self, destino, cabecalhos=None):
        self.send_response(303)
        self.send_header("Location", destino)
        self.send_header("Content-Length", "0")
        for nome, valor in (cabecalhos or []):
            self.send_header(nome, valor)
        self.end_headers()

    def render(self, status, conteudo, titulo):
        self.responder(status, pagina(conteudo, titulo, usuario=self.usuario))

    def usuario_logado(self):
        cookies = SimpleCookie(self.headers.get("Cookie", ""))
        if NOME_COOKIE in cookies:
            return ler_token(cookies[NOME_COOKIE].value) or ""
        return ""

    def cookie_login(self, email):
        extra = "; Secure" if COOKIE_SEGURO else ""
        return [("Set-Cookie",
                 f"{NOME_COOKIE}={criar_token(email)}; Path=/; HttpOnly; "
                 f"SameSite=Lax; Max-Age={SESSAO_SEGUNDOS}{extra}")]

    def cookie_logout(self):
        return [("Set-Cookie",
                 f"{NOME_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")]

    def ler_form(self):
        tamanho = int(self.headers.get("Content-Length", "0"))
        if tamanho < 0 or tamanho > 10000:
            raise ValueError("Tamanho de formulário inválido.")
        corpo = self.rfile.read(tamanho).decode("utf-8", errors="replace")
        return parse_qs(corpo)

    def do_GET(self):
        url = urlparse(self.path)
        self.usuario = self.usuario_logado()
        try:
            # ---- rotas públicas
            if url.path == "/login":
                if self.usuario:
                    return self.redirecionar("/")
                return self.responder(200, pagina_auth(
                    "Login", "/login",
                    link='Não tem conta? <a href="/cadastro">Cadastre-se</a>'))
            if url.path == "/cadastro":
                if self.usuario:
                    return self.redirecionar("/")
                return self.responder(200, pagina_auth(
                    "Cadastro", "/cadastro",
                    link='Já tem conta? <a href="/login">Entrar</a>'))
            if url.path == "/logout":
                return self.redirecionar("/login", self.cookie_logout())

            # ---- daqui para baixo exige login
            if not self.usuario:
                return self.redirecionar("/login")

            if url.path == "/":
                self.render(
                    200,
                    "<p>Use os formulários acima para pesquisar ou selecionar empresas.</p>",
                    "Início")

            elif url.path == "/buscar":
                parametros = parse_qs(url.query)
                termo = parametros.get("q", [""])[0][:120]
                ddd = normalizar_ddd(parametros.get("ddd", [""])[0][:5])
                ramo = parametros.get("ramo", [""])[0][:80]
                try:
                    quantidade = int(parametros.get("quantidade", ["100"])[0])
                except ValueError:
                    quantidade = 100
                quantidade = max(1, min(quantidade, MAX_GERACAO))
                resultados = buscar_empresas(termo, ddd, ramo, quantidade)
                filtros_txt = []
                if termo:
                    filtros_txt.append(f"termo: <strong>{escapar(termo)}</strong>")
                if ddd:
                    filtros_txt.append(f"DDD: <strong>{escapar(ddd)}</strong>")
                if ramo:
                    filtros_txt.append(f"ramo: <strong>{escapar(ramo)}</strong>")
                conteudo = (
                    f"<p>Filtros: {' | '.join(filtros_txt) or 'nenhum'}. "
                    f"Quantidade solicitada: {quantidade}. "
                    f"Resultados exibidos e registrados: {len(resultados)}.</p>"
                    + tabela_empresas(resultados)
                )
                self.render(200, conteudo, "Resultado da busca")

            elif url.path == "/historico":
                con = conectar()
                try:
                    historico = con.execute(f"""
                        SELECT e.cnpj, e.nome, e.telefone,
                               g.cnpj AS cnpj_usado, g.data_geracao
                        FROM empresas_geradas g
                        LEFT JOIN empresas e ON e.cnpj = g.cnpj
                        ORDER BY g.data_geracao DESC, g.cnpj
                        LIMIT 500
                    """).fetchall()
                finally:
                    con.close()

                if historico:
                    linhas = []
                    for item in historico:
                        linhas.append(f"""
                        <tr>
                            <td>{escapar(item['cnpj'] or item['cnpj_usado'])}</td>
                            <td>{escapar(item['nome'])}</td>
                            <td>{escapar(item['telefone'])}</td>
                            <td>{escapar(extrair_ddd(item['telefone']) or '—')}</td>
                            <td>{escapar(item['data_geracao'])}</td>
                        </tr>
                        """)
                    conteudo = f"""
                    <div class="tabela-wrap"><table>
                    <thead><tr><th>CNPJ</th><th>Nome fantasia</th>
                    <th>Telefone</th><th>DDD</th><th>Data de utilização</th></tr></thead>
                    <tbody>{''.join(linhas)}</tbody></table></div>
                    """
                else:
                    conteudo = "<p>Nenhum CNPJ utilizado ainda.</p>"
                self.render(200, conteudo, "Histórico de CNPJs utilizados")

            else:
                self.render(404, "<p>Página não encontrada.</p>", "Erro 404")
        except sqlite3.Error as erro:
            self.render(500, f"<p>Erro no banco de dados: {escapar(erro)}</p>", "Erro")

    def do_POST(self):
        url = urlparse(self.path)
        self.usuario = self.usuario_logado()
        try:
            # ---- rotas públicas
            if url.path == "/login":
                form = self.ler_form()
                email = form.get("email", [""])[0].strip().lower()
                senha = form.get("senha", [""])[0]
                if login_valido(email, senha):
                    return self.redirecionar("/", self.cookie_login(email))
                return self.responder(200, pagina_auth(
                    "Login", "/login", "E-mail ou senha incorretos.",
                    '<a href="/cadastro">Criar conta</a>'))
            if url.path == "/cadastro":
                form = self.ler_form()
                email = form.get("email", [""])[0].strip().lower()
                senha = form.get("senha", [""])[0]
                link = 'Já tem conta? <a href="/login">Entrar</a>'
                if "@" not in email or "." not in email or len(email) > 200:
                    return self.responder(200, pagina_auth(
                        "Cadastro", "/cadastro", "E-mail inválido.", link))
                if len(senha) < 6:
                    return self.responder(200, pagina_auth(
                        "Cadastro", "/cadastro",
                        "A senha precisa ter pelo menos 6 caracteres.", link))
                if not criar_usuario(email, senha):
                    return self.responder(200, pagina_auth(
                        "Cadastro", "/cadastro",
                        "Esse e-mail já está cadastrado.", link))
                return self.redirecionar("/", self.cookie_login(email))

            # ---- daqui para baixo exige login
            if not self.usuario:
                return self.redirecionar("/login")

            if url.path != "/gerar":
                self.render(404, "<p>Página não encontrada.</p>", "Erro 404")
                return

            parametros = self.ler_form()
            quantidade_texto = parametros.get("quantidade", ["10"])[0]
            try:
                quantidade = int(quantidade_texto)
            except ValueError:
                quantidade = 10
            quantidade = max(1, min(quantidade, MAX_GERACAO))
            ddd = normalizar_ddd(parametros.get("ddd", [""])[0][:5])
            ramo = parametros.get("ramo", [""])[0][:80]

            resultados = gerar_empresas(quantidade, ddd, ramo)
            ddd_txt = (f" (DDD {escapar(ddd)})" if ddd else "") + \
                      (f" (ramo {escapar(ramo)})" if ramo else "")
            conteudo = (
                f"<p>Solicitadas: {quantidade}{ddd_txt}. "
                f"Empresas encontradas e registradas: {len(resultados)}.</p>"
                + tabela_empresas(resultados)
            )
            self.render(200, conteudo, "Empresas geradas")
        except (ValueError, UnicodeError) as erro:
            self.render(400, f"<p>Dados inválidos: {escapar(erro)}</p>", "Erro")
        except sqlite3.Error as erro:
            self.render(500, f"<p>Erro no banco de dados: {escapar(erro)}</p>", "Erro")

    def log_message(self, formato, *args):
        print("[CNPJ Finder] " + (formato % args))


if __name__ == "__main__":
    preparar_banco()
    if not os.environ.get("SECRET_KEY"):
        print("AVISO: SECRET_KEY não definida. Usando chave temporária "
              "(os logins expiram ao reiniciar o servidor).")
    print(f"Extrator Bessa rodando em http://{HOST}:{PORTA}")
    print("Para encerrar, pressione Ctrl+C.")
    servidor = ThreadingHTTPServer((HOST, PORTA), CNPJHandler)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")
    finally:
        servidor.server_close()
