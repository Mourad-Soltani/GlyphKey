# GlyphKey

Local high-entropy secret generator & auditor for developers.

**Built by Mourad.Soltani**

## What you get

- Pure Python stdlib CLI (no third-party dependencies)
- Generate passwords, passphrases, hex tokens, and API keys
- Exact entropy calculation (bits) + strength label
- Approximate crack-time estimates
- JSON output for scripting
- Offline & private — secrets never leave your machine
- Health tests included

## Requirements

- Python 3.8+

## How to run in 30 seconds

```bash
# Clone or unzip
cd glyphkey

# Generate a strong password
python -m glyphkey.cli generate password --length 24 --json

# Generate a passphrase
python -m glyphkey.cli generate passphrase --words 7

# Analyze an existing secret
python -m glyphkey.cli analyze "your-secret-here"

# Run health tests
python -m unittest tests/test_health.py -v
```

## License

MIT — see LICENSE

Built by Mourad.Soltani
