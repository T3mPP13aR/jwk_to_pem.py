# jwk-to-pem.py

Convert an RSA public JWK or JWKS JSON file to PEM format.

## Features

- Supports standalone JWK JSON
- Supports JWKS (`keys` array)
- Validates RSA public key fields
- Outputs PEM to stdout or file

## Requirements

- Python 3.9+
- cryptography

## Usage
### To Terminal:
```python
python3 jwk_to_pem.py --jwk-file public.jwk
```
### To File:
```python
python3 jwk_to_pem.py --jwk-file public.jwk --out public.pem
```
## Install

```bash
pip install cryptography
```
