# Buyer notes — GlyphKey

## What you get
- Complete pure-Python CLI source for generating and auditing high-entropy secrets
- Zero external dependencies (stdlib only)
- Modes: password, passphrase, hex token, API key
- Exact entropy bits, strength labels, crack-time estimates
- JSON output for automation
- Health tests that verify core behavior

## How to run
1. Unzip the archive
2. Ensure Python 3.8+ is installed
3. From the project root:
   ```
   python -m glyphkey.cli generate password --length 20
   python -m glyphkey.cli generate passphrase --words 6
   python -m unittest tests/test_health.py -v
   ```

## Requirements
- Python 3.8 or newer
- No internet connection required after download
- Works on Linux, macOS, Windows

Built by Mourad.Soltani
