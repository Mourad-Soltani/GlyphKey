#!/usr/bin/env python3
"""
GlyphKey CLI — generate and audit high-entropy secrets.
Built by Mourad.Soltani
"""

import argparse
import json
import math
import secrets
import string
import sys
from typing import Dict, List, Optional, Tuple

# Short EFF-inspired wordlist (subset for offline use, ~256 common words)
WORDLIST = [
    "able", "acid", "aged", "also", "area", "army", "away", "baby", "back", "ball",
    "band", "bank", "base", "bath", "bear", "beat", "been", "bell", "belt", "bend",
    "best", "bill", "bird", "blow", "blue", "boat", "body", "bomb", "bond", "bone",
    "book", "boom", "born", "boss", "both", "bowl", "bulk", "burn", "bush", "busy",
    "call", "calm", "came", "camp", "card", "care", "case", "cash", "cast", "cave",
    "cell", "chat", "chip", "city", "club", "coal", "coat", "code", "cold", "come",
    "cook", "cool", "cope", "copy", "core", "cost", "crew", "crop", "dark", "data",
    "date", "dawn", "days", "dead", "deal", "dean", "dear", "debt", "deep", "deny",
    "desk", "dial", "diet", "disc", "disk", "does", "done", "door", "dose", "down",
    "draw", "drew", "drop", "drug", "dual", "duke", "dust", "duty", "each", "earn",
    "ease", "east", "easy", "edge", "else", "even", "ever", "evil", "exit", "face",
    "fact", "fail", "fair", "fall", "farm", "fast", "fate", "fear", "feed", "feel",
    "feet", "fell", "felt", "file", "fill", "film", "find", "fine", "fire", "firm",
    "fish", "five", "flat", "flow", "foam", "fold", "font", "food", "foot", "ford",
    "form", "fort", "four", "free", "from", "fuel", "full", "fund", "gain", "game",
    "gate", "gave", "gear", "gene", "gift", "girl", "give", "glad", "goal", "goes",
    "gold", "golf", "gone", "good", "gray", "grew", "grey", "grow", "gulf", "hair",
    "half", "hall", "hand", "hang", "hard", "harm", "hate", "have", "head", "hear",
    "heat", "held", "hell", "help", "here", "hero", "high", "hill", "hire", "hold",
    "hole", "holy", "home", "hope", "host", "hour", "huge", "hung", "hunt", "hurt",
    "idea", "inch", "into", "iron", "item", "jack", "jane", "jean", "john", "join",
    "jump", "jury", "just", "keen", "keep", "kent", "kept", "kick", "kill", "kind",
    "king", "knee", "knew", "know", "lack", "lady", "laid", "lake", "land", "lane",
    "last", "late", "lead", "left", "less", "life", "lift", "like", "line", "link",
    "list", "live", "load", "loan", "lock", "logo", "long", "look", "lord", "lose",
    "loss", "lost", "love", "luck", "made", "mail", "main", "make", "male", "mall",
    "many", "mark", "mass", "matt", "meal", "mean", "meat", "meet", "menu", "mere",
    "mike", "mile", "milk", "mill", "mind", "mine", "miss", "mode", "mood", "moon",
    "more", "most", "move", "much", "must", "name", "navy", "near", "neck", "need",
    "news", "next", "nice", "nick", "nine", "none", "nose", "note", "okay", "once",
    "only", "onto", "open", "oral", "over", "pace", "pack", "page", "paid", "pain",
    "pair", "palm", "park", "part", "pass", "past", "path", "peak", "pick", "pile",
    "pine", "pink", "plan", "play", "plot", "plug", "plus", "poll", "pool", "poor",
    "port", "post", "pull", "pure", "push", "race", "rail", "rain", "rank", "rare",
    "rate", "read", "real", "rear", "rely", "rent", "rest", "rice", "rich", "ride",
    "ring", "rise", "risk", "road", "rock", "role", "roll", "roof", "room", "root",
    "rose", "rule", "rush", "ruth", "safe", "said", "sake", "sale", "salt", "same",
    "sand", "save", "seat", "seed", "seek", "seem", "seen", "self", "sell", "send",
    "sent", "sept", "ship", "shop", "shot", "show", "shut", "sick", "side", "sign",
    "site", "size", "skin", "slip", "slow", "snow", "soft", "soil", "sold", "sole",
    "some", "song", "soon", "sort", "soul", "spot", "star", "stay", "step", "stop",
    "such", "suit", "sure", "take", "tale", "talk", "tall", "tank", "tape", "task",
    "team", "tech", "tell", "tend", "term", "test", "text", "than", "that", "them",
    "then", "they", "thin", "this", "thus", "till", "time", "tiny", "told", "toll",
    "tone", "tony", "took", "tool", "tour", "town", "tree", "trip", "true", "tune",
    "turn", "twin", "type", "unit", "upon", "used", "user", "vary", "vast", "very",
    "vice", "view", "vote", "wage", "wait", "wake", "walk", "wall", "want", "ward",
    "warm", "warn", "wash", "wave", "ways", "weak", "wear", "week", "well", "went",
    "were", "west", "what", "when", "whom", "wide", "wife", "wild", "will", "wind",
    "wine", "wing", "wire", "wise", "wish", "with", "wood", "word", "wore", "work",
    "yard", "yeah", "year", "your", "zero", "zone"
]

CHARSETS = {
    "alnum": string.ascii_letters + string.digits,
    "alnum-symbols": string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?",
    "hex": "0123456789abcdef",
    "base64url": string.ascii_letters + string.digits + "-_",
}


def calculate_entropy(length: int, pool_size: int) -> float:
    """Exact entropy in bits for uniform sampling from pool of size R, length L."""
    if pool_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(pool_size)


def strength_label(bits: float) -> str:
    if bits < 28:
        return "very-weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "reasonable"
    if bits < 80:
        return "strong"
    if bits < 128:
        return "very-strong"
    return "excellent"


def crack_time_years(bits: float, guesses_per_second: float = 1e11) -> float:
    """Approximate years to crack at given guesses/sec (offline SHA-256-ish)."""
    if bits <= 0:
        return 0.0
    seconds = (2 ** bits) / guesses_per_second
    return seconds / (365.25 * 24 * 3600)


def generate_password(length: int = 20, charset: str = "alnum-symbols") -> Tuple[str, float]:
    pool = CHARSETS.get(charset, CHARSETS["alnum-symbols"])
    pwd = "".join(secrets.choice(pool) for _ in range(length))
    entropy = calculate_entropy(length, len(pool))
    return pwd, entropy


def generate_passphrase(words: int = 6, separator: str = "-") -> Tuple[str, float]:
    chosen = [secrets.choice(WORDLIST) for _ in range(words)]
    phrase = separator.join(chosen)
    # Entropy from wordlist size
    entropy = calculate_entropy(words, len(WORDLIST))
    return phrase, entropy


def generate_hex(bytes_len: int = 32) -> Tuple[str, float]:
    token = secrets.token_hex(bytes_len)
    entropy = bytes_len * 8
    return token, entropy


def generate_api_key(prefix: str = "gk_", length: int = 32) -> Tuple[str, float]:
    body, _ = generate_password(length, "alnum")
    key = f"{prefix}{body}"
    entropy = calculate_entropy(length, len(CHARSETS["alnum"]))
    return key, entropy


def analyze(secret: str) -> Dict:
    """Analyze an existing secret's approximate entropy based on observed chars."""
    if not secret:
        return {"error": "empty secret"}
    observed = set(secret)
    # Conservative pool estimate
    pool = 1
    if any(c.islower() for c in observed):
        pool += 26
    if any(c.isupper() for c in observed):
        pool += 26
    if any(c.isdigit() for c in observed):
        pool += 10
    if any(not c.isalnum() for c in observed):
        pool += 32
    bits = calculate_entropy(len(secret), max(pool, 2))
    return {
        "length": len(secret),
        "unique_chars": len(observed),
        "estimated_pool": pool,
        "entropy_bits": round(bits, 2),
        "strength": strength_label(bits),
        "crack_years_gpu": round(crack_time_years(bits, 1e11), 2),
    }


def cmd_generate(args) -> None:
    mode = args.mode
    if mode == "password":
        secret, bits = generate_password(args.length, args.charset)
    elif mode == "passphrase":
        secret, bits = generate_passphrase(args.words, args.separator)
    elif mode == "hex":
        secret, bits = generate_hex(args.bytes)
    elif mode == "apikey":
        secret, bits = generate_api_key(args.prefix, args.length)
    else:
        print(f"Unknown mode: {mode}", file=sys.stderr)
        sys.exit(1)

    result = {
        "secret": secret,
        "entropy_bits": round(bits, 2),
        "strength": strength_label(bits),
        "mode": mode,
        "crack_years_1e11": round(crack_time_years(bits), 2),
        "version": __import__("glyphkey").__version__,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(secret)
        print(f"  entropy: {result['entropy_bits']} bits ({result['strength']})")
        print(f"  crack time (~1e11 guesses/s): {result['crack_years_1e11']} years")


def cmd_analyze(args) -> None:
    secret = args.secret or sys.stdin.read().strip()
    result = analyze(secret)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for k, v in result.items():
            print(f"{k}: {v}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="glyphkey",
        description="GlyphKey — local high-entropy secret generator & auditor. Built by Mourad.Soltani",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a new secret")
    gen.add_argument("mode", choices=["password", "passphrase", "hex", "apikey"])
    gen.add_argument("--length", type=int, default=20)
    gen.add_argument("--charset", default="alnum-symbols", choices=list(CHARSETS.keys()))
    gen.add_argument("--words", type=int, default=6)
    gen.add_argument("--separator", default="-")
    gen.add_argument("--bytes", type=int, default=32)
    gen.add_argument("--prefix", default="gk_")
    gen.add_argument("--json", action="store_true")
    gen.set_defaults(func=cmd_generate)

    ana = sub.add_parser("analyze", help="Analyze an existing secret")
    ana.add_argument("secret", nargs="?", default="")
    ana.add_argument("--json", action="store_true")
    ana.set_defaults(func=cmd_analyze)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
