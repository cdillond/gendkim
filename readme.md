# About
gendkim is a CLI tool for generating DKIM Ed25519-type keys and DNS records. It accepts the following options:
- `from` [string] optional input path of the PEM-encoded Ed25519 private key; if no value is provided, a new key is generated
- `privkey` [string] output path of the PEM-encoded Ed25519 private key (default "privkey.pem")
- `pubkey` [string] output path of the PEM-encoded Ed25519 public key (default "pubkey.pem")
- `record` [string] output path of the DKIM record content (default "dkim-record.txt")
- `seed` [string] optional input path of the Ed25519 private key seed
