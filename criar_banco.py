
import csv
import os
import sqlite3

PASTA = os.path.dirname(os.path.abspath(__file__))
CSV_ARQUIVO = os.path.join(PASTA, "estabelecimentos_amostra.csv")
BANCO = os.path.join(PASTA, "cnpj_finder.db")

conexao = sqlite3.connect(BANCO)
cursor = conexao.cursor()

cursor.execute("DROP TABLE IF EXISTS empresas")
cursor.execute("""
    CREATE TABLE empresas (
        cnpj TEXT PRIMARY KEY,
        nome TEXT,
        telefone TEXT,
        cnae_principal TEXT,
        cnae_secundario TEXT
    )
""")

with open(CSV_ARQUIVO, encoding="utf-8", newline="") as arquivo:
    leitor = csv.DictReader(arquivo, delimiter=";")
    dados = [
        (
            linha["cnpj"],
            linha["nome"],
            linha["telefone"],
            linha["cnae_principal"],
            linha["cnae_secundario"]
        )
        for linha in leitor
    ]

cursor.executemany("""
    INSERT OR REPLACE INTO empresas
    (cnpj, nome, telefone, cnae_principal, cnae_secundario)
    VALUES (?, ?, ?, ?, ?)
""", dados)

cursor.execute("CREATE INDEX idx_nome ON empresas(nome)")
cursor.execute("CREATE INDEX idx_cnae_principal ON empresas(cnae_principal)")
cursor.execute("CREATE INDEX idx_cnae_secundario ON empresas(cnae_secundario)")

conexao.commit()
conexao.close()

print(f"Banco atualizado! Registros: {len(dados):,}")
