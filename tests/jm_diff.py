#!/usr/bin/env python3
# Differential test: jsonmini (via tests/jm_dump) vs Python's json module.
#  1. random valid documents (nesting, unicode incl. astral, escapes,
#     numbers) must parse to the same value;
#  2. random corruptions must be rejected exactly when Python rejects them
#     (Python is lenient about NaN/Infinity and lone surrogates; those inputs
#     are skipped).
# Usage: jm_diff.py <jm_dump> [iterations]
import json, random, subprocess, sys

dump, iters = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 2000
rnd = random.Random(1234)
alphabet = 'aZ09 "\\/\b\f\n\r\t\x01' + 'é€\U0001F600中'

def rstr():
    return ''.join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 8)))

def rval(d=0):
    k = rnd.randint(0, 7 if d < 6 else 4)
    if k == 0: return None
    if k == 1: return rnd.choice([True, False])
    if k == 2: return rnd.randint(-10**12, 10**12)
    if k == 3: return rnd.uniform(-1e6, 1e6)
    if k == 4: return rstr()
    if k in (5, 6): return [rval(d + 1) for _ in range(rnd.randint(0, 4))]
    return {rstr(): rval(d + 1) for _ in range(rnd.randint(0, 4))}

def norm(v):
    # jsonmini keeps numbers as doubles: compare Python ints the same way.
    if isinstance(v, bool) or v is None or isinstance(v, str): return v
    if isinstance(v, (int, float)): return float(v)
    if isinstance(v, list): return [norm(x) for x in v]
    return {k: norm(x) for k, x in v.items()}

def run(text):
    return subprocess.run([dump], input=text.encode('utf-8', 'surrogatepass'), capture_output=True).stdout.decode()

fails = 0
for i in range(iters):
    v = rval()
    text = json.dumps(v, ensure_ascii=rnd.random() < 0.5, indent=rnd.choice([None, 1]))
    out = run(text)
    if out.strip() == 'INVALID' or norm(json.loads(out)) != norm(json.loads(text)):
        print('FAIL valid:', text[:200], '->', out[:200]); fails += 1
    # Corruption: delete / insert / replace one character.
    t = list(text)
    pos = rnd.randrange(len(t) + 1)
    op = rnd.randint(0, 2)
    if op == 0 and t: del t[min(pos, len(t) - 1)]
    elif op == 1: t.insert(pos, rnd.choice('{}[],:"\\x0 -e.'))
    elif t: t[min(pos, len(t) - 1)] = rnd.choice('{}[],:"\\x0 -e.')
    bad = ''.join(t)
    try:
        ref = json.loads(bad)
        ok = True
    except Exception:
        ok = False
    if any(w in bad for w in ('NaN', 'Infinity')):
        continue
    if ok and any(0xD800 <= ord(ch) <= 0xDFFF for ch in json.dumps(ref, ensure_ascii=False)):
        continue
    out = run(bad).strip()
    if (out == 'INVALID') == ok:
        print(f'FAIL corrupt (python ok={ok}):', repr(bad[:200]), '->', out[:120]); fails += 1
    elif ok and norm(json.loads(out)) != norm(ref):
        print('FAIL corrupt value:', repr(bad[:200]), '->', out[:200]); fails += 1
print(f'{fails} failure(s) in {iters} documents')
sys.exit(1 if fails else 0)
