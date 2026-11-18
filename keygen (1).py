#!/usr/bin/env python3
"""
Gerador de licencas para o plugin (Ed25519).

Pode ser usado com dois cliques (menu interativo) ou pelo terminal:
  python keygen.py gen                 -> cria private.key e mostra a chave publica em formato C++
  python keygen.py sign email@x.com    -> mostra a chave de ativacao para esse e-mail

Requer: pip install cryptography
GUARDE private.key em local seguro. NUNCA coloque no GitHub nem no plugin.
"""
import sys
import base64
from pathlib import Path

PRODUCT = "MEUPLUGIN"  # troque pelo nome do seu plugin (igual no license.h)

# private.key fica sempre ao lado do script, nao importa de onde ele e aberto
KEY_FILE = Path(__file__).resolve().parent / "private.key"


def pausa():
    try:
        input("\nPressione Enter para fechar...")
    except EOFError:
        pass


try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("Falta instalar a biblioteca 'cryptography'.")
    print("Abra o Prompt de Comando e rode:\n")
    print("    pip install cryptography\n")
    print("Depois abra este script de novo.")
    pausa()
    sys.exit(1)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def gen():
    if KEY_FILE.exists():
        print("private.key ja existe. Apague manualmente se quiser gerar outra")
        print("(isso invalida todas as licencas ja vendidas).")
        return
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    KEY_FILE.write_bytes(seed)
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    print(f"private.key criada em: {KEY_FILE}")
    print("GUARDE EM LOCAL SEGURO e faca backup.\n")
    print("Cole isto no license.h (PUBKEY):\n")
    print("{ " + ", ".join(f"0x{b:02x}" for b in pub) + " }")


def sign(email: str):
    if not KEY_FILE.exists():
        print("Ainda nao existe private.key. Gere primeiro (opcao 1).")
        return
    priv = Ed25519PrivateKey.from_private_bytes(KEY_FILE.read_bytes())
    email = email.strip().lower()
    if not email:
        print("E-mail vazio.")
        return
    sig = priv.sign(f"{PRODUCT}|{email}".encode())
    print("\nConteudo do license.txt para o cliente:\n")
    print(email)
    print(b64u(sig))


def menu():
    print("=== Gerador de licencas ===\n")
    print("1) Gerar par de chaves (so na primeira vez)")
    print("2) Gerar licenca para um cliente\n")
    op = input("Escolha 1 ou 2: ").strip()
    print()
    if op == "1":
        gen()
    elif op == "2":
        sign(input("E-mail do cliente: "))
    else:
        print("Opcao invalida.")


if __name__ == "__main__":
    interativo = len(sys.argv) == 1
    if len(sys.argv) >= 2 and sys.argv[1] == "gen":
        gen()
    elif len(sys.argv) == 3 and sys.argv[1] == "sign":
        sign(sys.argv[2])
    elif interativo:
        menu()
    else:
        print(__doc__)
    if interativo:
        pausa()
