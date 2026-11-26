
from Crypto.PublicKey import RSA
from pathlib import Path
from rsa_secure import generate_keys


KEY_FOLDER = Path(__file__).parent / "keys"

KEY_FOLDER.mkdir(exist_ok=True)


# Generate and Save User Keys
def create_user(user, bits=2048):

    public_path = KEY_FOLDER / f"{user}_public.pem"
    private_path = KEY_FOLDER / f"{user}_private.pem"

    if public_path.exists() or private_path.exists():
        print(f"Key files for {user} already exist.")
        return

    public_key, private_key = generate_keys(bits)

    public_path.write_bytes(
        public_key.export_key()
    )

    private_path.write_bytes(
        private_key.export_key()
    )

    print(f"\nUser: {user}")
    print(f"Key size: {bits} bits")
    print(f"Public key: {public_path.name}")
    print(f"Private key: {private_path.name}")
    print("Keys successfully generated.")


# Load Public Key
def load_public_key(user):

    path = KEY_FOLDER / f"{user}_public.pem"

    return RSA.import_key(path.read_bytes())


# Load Private Key
def load_private_key(user):

    path = KEY_FOLDER / f"{user}_private.pem"

    return RSA.import_key(path.read_bytes())


# Main Program
if __name__ == "__main__":

    create_user("alice", 2048)
    create_user("bob", 2048)
