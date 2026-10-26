"""
Classifica as empresas do banco em "ramos" e grava na coluna `ramo`.

Como usar (na mesma pasta do cnpj_finder.db):
    python classificar_ramos.py

1) Se a tabela `empresas` tiver uma coluna de CNAE (cnae, cnae_fiscal,
   cnae_principal...), o ramo vem da divisão do CNAE (exato).
2) Para empresas sem CNAE, tenta adivinhar pelas palavras do nome
   (aproximado). O que não se encaixar vira "Outros".

Pode rodar de novo quando quiser: só preenche quem ainda está sem ramo.
Use --refazer para reclassificar todo mundo.
"""
import os
import re
import sqlite3
import sys
import unicodedata

BANCO = os.environ.get(
    "BANCO",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cnpj_finder.db"),
)

CNAE_CANDIDATAS = [
    "cnae_fiscal_principal", "cnae_principal", "cnae_fiscal",
    "cnae", "atividade_principal", "cnae_codigo",
]

# Divisão do CNAE (2 primeiros dígitos) -> ramo
FAIXAS = [
    (1, 3, "Agropecuária"),
    (5, 9, "Indústria extrativa"),
    (10, 33, "Indústria"),
    (35, 39, "Energia, água e resíduos"),
    (41, 43, "Construção"),
    (45, 45, "Automotivo (comércio e reparo)"),
    (46, 46, "Comércio atacadista"),
    (47, 47, "Comércio varejista"),
    (49, 53, "Transporte e logística"),
    (55, 55, "Hospedagem e turismo"),
    (56, 56, "Alimentação (bares e restaurantes)"),
    (58, 63, "Tecnologia e comunicação"),
    (64, 66, "Financeiro e seguros"),
    (68, 68, "Imobiliário"),
    (69, 75, "Serviços profissionais"),
    (77, 82, "Serviços administrativos"),
    (84, 84, "Administração pública"),
    (85, 85, "Educação"),
    (86, 88, "Saúde"),
    (90, 93, "Arte, cultura e esporte"),
    (94, 94, "Associações e igrejas"),
    (95, 95, "Reparação de equipamentos"),
    (96, 96, "Serviços pessoais (beleza, lavanderia...)"),
    (97, 99, "Outros serviços"),
]

# Plano B: palavras no nome (sem acento, minúsculas). A ordem importa.
PALAVRAS = [
    ("Alimentação (bares e restaurantes)", [
        "restaurante", "lanchonete", "padaria", "pizzaria", "hamburg",
        "cafe", "sorveteria", "acai", "confeitaria", "churrascaria",
        "marmita", "doceria", "pastelaria", "bar e ", "boteco"]),
    ("Serviços pessoais (beleza, lavanderia...)", [
        "salao", "barbearia", "estetica", "cabeleireir", "manicure",
        "beleza", "lavanderia", "studio de unha"]),
    ("Saúde", [
        "clinica", "odonto", "dentista", "farmacia", "drogaria",
        "laboratorio", "medic", "fisioterap", "hospital", "psicolog",
        "veterin", "nutri"]),
    ("Construção", [
        "construtora", "construcao", "engenharia", "empreiteira",
        "reformas", "materiais de constru", "pintura", "eletrica"]),
    ("Tecnologia e comunicação", [
        "tecnologia", "software", "informatica", "sistemas", "internet",
        "telecom", "marketing", "publicidade", "comunicacao"]),
    ("Transporte e logística", [
        "transporte", "transportadora", "logistica", "frete", "motoboy",
        "entregas", "mudancas"]),
    ("Educação", [
        "escola", "colegio", "curso", "ensino", "educacao", "creche",
        "idiomas"]),
    ("Automotivo (comércio e reparo)", [
        "auto pecas", "autopecas", "mecanica", "oficina", "veiculos",
        "motos", "funilaria", "automoveis", "borracharia", "auto center"]),
    ("Serviços profissionais", [
        "advocacia", "advogados", "contabil", "contabilidade",
        "consultoria", "assessoria", "arquitetura", "despachante"]),
    ("Imobiliário", ["imobiliaria", "imoveis", "incorporadora"]),
    ("Agropecuária", [
        "agro", "fazenda", "agricola", "pecuaria", "sitio"]),
    ("Indústria", [
        "industria", "fabrica", "confeccoes", "metalurgica", "moveis",
        "artefatos", "plasticos", "graficas", "grafica"]),
    ("Comércio varejista", [
        "comercio", "loja", "magazine", "mercado", "supermercado",
        "variedades", "boutique", "moda", "calcados", "armarinho"]),
]


def sem_acento(texto):
    base = unicodedata.normalize("NFKD", str(texto or ""))
    return "".join(c for c in base if not unicodedata.combining(c)).lower()


def ramo_por_cnae(valor):
    digitos = re.sub(r"\D", "", str(valor or ""))
    if not digitos or len(digitos) > 7:
        return None
    divisao = int(digitos.zfill(7)[:2])
    for ini, fim, nome in FAIXAS:
        if ini <= divisao <= fim:
            return nome
    return None


def ramo_por_nome(nome):
    n = " " + sem_acento(nome) + " "
    for ramo, palavras in PALAVRAS:
        if any(p in n for p in palavras):
            return ramo
    return None


def main():
    refazer = "--refazer" in sys.argv
    if not os.path.exists(BANCO):
        sys.exit(f"Banco não encontrado: {BANCO}")

    con = sqlite3.connect(BANCO, timeout=60)
    con.row_factory = sqlite3.Row
    colunas = {l["name"].lower(): l["name"]
               for l in con.execute("PRAGMA table_info(empresas)")}
    if not colunas:
        sys.exit("Tabela 'empresas' não encontrada.")

    if "ramo" not in colunas:
        con.execute("ALTER TABLE empresas ADD COLUMN ramo TEXT")
    if refazer:
        con.execute("UPDATE empresas SET ramo = NULL")
    con.commit()

    # ---- 1) por CNAE
    col_cnae = next((colunas[c] for c in CNAE_CANDIDATAS if c in colunas), None)
    if col_cnae:
        print(f"Usando a coluna de CNAE: {col_cnae}")
        con.execute(
            f'CREATE INDEX IF NOT EXISTS idx_empresas_cnae_tmp '
            f'ON empresas("{col_cnae}")')
        valores = [r[0] for r in con.execute(
            f'SELECT DISTINCT "{col_cnae}" FROM empresas WHERE ramo IS NULL')]
        for v in valores:
            ramo = ramo_por_cnae(v)
            if ramo:
                con.execute(
                    f'UPDATE empresas SET ramo = ? '
                    f'WHERE ramo IS NULL AND "{col_cnae}" IS ?', (ramo, v))
        con.commit()
        con.execute("DROP INDEX IF EXISTS idx_empresas_cnae_tmp")
    else:
        print("Nenhuma coluna de CNAE encontrada; usando palavras do nome.")

    # ---- 2) por palavras do nome (quem ainda está sem ramo)
    ultimo = 0
    while True:
        lote = con.execute(
            "SELECT rowid AS id, nome FROM empresas "
            "WHERE ramo IS NULL AND rowid > ? ORDER BY rowid LIMIT 50000",
            (ultimo,)).fetchall()
        if not lote:
            break
        ultimo = lote[-1]["id"]
        con.executemany(
            "UPDATE empresas SET ramo = ? WHERE rowid = ?",
            [(ramo_por_nome(r["nome"]) or "Outros", r["id"]) for r in lote])
        con.commit()
        print(f"  classificadas até o registro {ultimo}...")

    # ---- 3) índice e lista de ramos (usada no menu do site)
    con.execute("CREATE INDEX IF NOT EXISTS idx_empresas_ramo ON empresas(ramo)")
    con.execute("DROP TABLE IF EXISTS ramos_disponiveis")
    con.execute(
        "CREATE TABLE ramos_disponiveis (ramo TEXT PRIMARY KEY, total INTEGER)")
    con.execute(
        "INSERT INTO ramos_disponiveis "
        "SELECT ramo, COUNT(*) FROM empresas "
        "WHERE ramo IS NOT NULL GROUP BY ramo")
    con.commit()

    print("\nResumo por ramo:")
    for r in con.execute(
            "SELECT ramo, total FROM ramos_disponiveis ORDER BY total DESC"):
        print(f"  {r['ramo']:<45} {r['total']:>10,}")
    con.close()


if __name__ == "__main__":
    main()
