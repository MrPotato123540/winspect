// sqlite - read-only SQLite 3 file reader (see sqlite.h)

#include "sqlite.h"

#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH     32
#define MAX_COLS      256
#define MAX_OVERFLOW  100000

static uint16_t be16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const unsigned char *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

// Varint: up to 9 bytes, big-endian 7-bit groups, the 9th byte uses all 8 bits.
static int varint(const unsigned char *p, const unsigned char *end, uint64_t *v)
{
    uint64_t x = 0;
    for (int i = 0; i < 9; i++) {
        if (p + i >= end) return 0;
        if (i == 8) { x = (x << 8) | p[i]; *v = x; return 9; }
        x = (x << 7) | (p[i] & 0x7F);
        if (!(p[i] & 0x80)) { *v = x; return i + 1; }
    }
    return 0;
}

// Page pgno (1-based) or NULL.
static const unsigned char *page(const sqlite_db *db, uint32_t pgno)
{
    if (pgno == 0) return NULL;
    if (db->wal && pgno <= db->wal_pages && db->wal[pgno - 1]) return db->wal[pgno - 1];
    // Only pages that really are in the main file (a WAL commit may say the
    // database is larger; pages it did not write do not exist anywhere).
    if ((size_t)pgno > db->n / db->page_size) return NULL;
    return db->d + (size_t)(pgno - 1) * db->page_size;
}

int sqlite_open(sqlite_db *db, const unsigned char *d, size_t n)
{
    memset(db, 0, sizeof *db);
    if (n < 100 || memcmp(d, "SQLite format 3", 16) != 0) return -1;
    uint32_t ps = be16(d + 16);
    if (ps == 1) ps = 65536;
    if (ps < 512 || ps > 65536 || (ps & (ps - 1))) return -1;
    db->d = d;
    db->n = n;
    db->page_size = ps;
    db->usable = ps - d[20];
    if (db->usable < 480) return -1;
    db->pages = (uint32_t)(n / ps);
    db->encoding = (int)be32(d + 56);
    if (db->encoding < 1 || db->encoding > 3) db->encoding = 1;
    return db->pages ? 0 : -1;
}

void sqlite_close(sqlite_db *db)
{
    free((void *)db->wal);
    db->wal = NULL;
}

int sqlite_apply_wal(sqlite_db *db, const unsigned char *w, size_t n)
{
    // WAL header (32 bytes): magic 0x377f0682/0x377f0683, version, page size,
    // checkpoint seq, salt-1, salt-2, checksums. Frames: 24-byte header (page
    // number, db size after commit or 0, salt-1, salt-2, checksums) + page.
    if (n < 32) return -1;
    uint32_t magic = be32(w);
    if (magic != 0x377f0682 && magic != 0x377f0683) return -1;
    uint32_t ps = be32(w + 8);
    if (ps != db->page_size) return -1;
    uint32_t salt1 = be32(w + 16), salt2 = be32(w + 20);
    size_t fsz = 24 + (size_t)ps;
    size_t frames = (n - 32) / fsz;
    // First pass: how far do committed frames with the current salts go?
    size_t last_commit = 0;
    uint32_t maxpg = db->pages, commit_size = 0;
    for (size_t i = 0; i < frames; i++) {
        const unsigned char *f = w + 32 + i * fsz;
        if (be32(f + 8) != salt1 || be32(f + 12) != salt2) break;      // older generation
        if (be32(f) > maxpg) maxpg = be32(f);
        if (be32(f + 4)) { last_commit = i + 1; commit_size = be32(f + 4); }
    }
    if (last_commit == 0) return 0;
    if (maxpg > 1u << 24) return -1;
    const unsigned char **map = (const unsigned char **)calloc(maxpg, sizeof *map);
    if (map == NULL) return -1;
    for (size_t i = 0; i < last_commit; i++) {
        const unsigned char *f = w + 32 + i * fsz;
        uint32_t pg = be32(f);
        if (pg >= 1 && pg <= maxpg) map[pg - 1] = f + 24;
    }
    free((void *)db->wal);
    db->wal = map;
    db->wal_pages = maxpg;
    // The database grows to the size recorded at the last commit.
    if (commit_size > db->pages) db->pages = commit_size;
    // Before a checkpoint the newest header (text encoding!) is the WAL's copy
    // of page 1, not the main file's.
    if (map[0]) {
        int enc = (int)be32(map[0] + 56);
        if (enc >= 1 && enc <= 3) db->encoding = enc;
    }
    return (int)last_commit;
}

// ---- records ----------------------------------------------------------------

// UTF-16 text (le/be) -> UTF-8 into a scratch buffer owned by the caller.
static size_t u16_to_u8(const unsigned char *s, size_t bytes, int be, unsigned char *o, size_t on)
{
    size_t k = 0;
    for (size_t i = 0; i + 1 < bytes; i += 2) {
        uint32_t c = be ? (uint32_t)((s[i] << 8) | s[i + 1]) : (uint32_t)(s[i] | (s[i + 1] << 8));
        if (c >= 0xD800 && c <= 0xDBFF && i + 3 < bytes) {
            uint32_t lo = be ? (uint32_t)((s[i + 2] << 8) | s[i + 3]) : (uint32_t)(s[i + 2] | (s[i + 3] << 8));
            if (lo >= 0xDC00 && lo <= 0xDFFF) { c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); i += 2; }
            else c = '?';
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            c = '?';
        }
        unsigned char b[4];
        size_t len;
        if (c < 0x80) { b[0] = (unsigned char)c; len = 1; }
        else if (c < 0x800) { b[0] = (unsigned char)(0xC0 | (c >> 6)); b[1] = (unsigned char)(0x80 | (c & 0x3F)); len = 2; }
        else if (c < 0x10000) { b[0] = (unsigned char)(0xE0 | (c >> 12)); b[1] = (unsigned char)(0x80 | ((c >> 6) & 0x3F)); b[2] = (unsigned char)(0x80 | (c & 0x3F)); len = 3; }
        else { b[0] = (unsigned char)(0xF0 | (c >> 18)); b[1] = (unsigned char)(0x80 | ((c >> 12) & 0x3F)); b[2] = (unsigned char)(0x80 | ((c >> 6) & 0x3F)); b[3] = (unsigned char)(0x80 | (c & 0x3F)); len = 4; }
        if (k + len > on) break;
        memcpy(o + k, b, len);
        k += len;
    }
    return k;
}

static void decode_record(const sqlite_db *db, int64_t rowid, const unsigned char *rec, size_t n,
                          sqlite_row_cb cb, void *ctx)
{
    uint64_t hsize;
    int k = varint(rec, rec + n, &hsize);
    if (k == 0 || hsize > n || hsize < (uint64_t)k) return;
    sqlite_val cols[MAX_COLS];
    unsigned char *u8 = NULL;           // UTF-16 conversions live here
    size_t u8n = 0, u8cap = 0;
    // Two passes: sizes first (for the UTF-16 scratch size), then values.
    if (db->encoding != 1) { u8cap = n * 2 + 16; u8 = (unsigned char *)malloc(u8cap); if (u8 == NULL) return; }
    const unsigned char *h = rec + k, *hend = rec + hsize, *body = rec + hsize, *end = rec + n;
    int nc = 0;
    while (h < hend && nc < MAX_COLS) {
        uint64_t st;
        int l = varint(h, hend, &st);
        if (l == 0) break;
        h += l;
        sqlite_val *v = &cols[nc++];
        memset(v, 0, sizeof *v);
        size_t len = 0;
        switch (st) {
        case 0: v->type = SQ_NULL; break;
        case 1: case 2: case 3: case 4: case 5: case 6: {
            static const size_t sz[] = { 0, 1, 2, 3, 4, 6, 8 };
            len = sz[st];
            if ((size_t)(end - body) < len) { len = 0; v->type = SQ_NULL; break; }
            int64_t x = (body[0] & 0x80) ? -1 : 0;
            for (size_t i = 0; i < len; i++) x = (int64_t)(((uint64_t)x << 8) | body[i]);
            v->type = SQ_INT;
            v->i = x;
            break;
        }
        case 7: {
            len = 8;
            if ((size_t)(end - body) < 8) { len = 0; v->type = SQ_NULL; break; }
            uint64_t bits = 0;
            for (int i = 0; i < 8; i++) bits = (bits << 8) | body[i];
            memcpy(&v->f, &bits, 8);
            v->type = SQ_FLOAT;
            break;
        }
        case 8: v->type = SQ_INT; v->i = 0; break;
        case 9: v->type = SQ_INT; v->i = 1; break;
        case 10: case 11: v->type = SQ_NULL; break;          // reserved
        default:
            len = (size_t)((st - 12) / 2);
            if ((size_t)(end - body) < len) len = (size_t)(end - body);
            v->p = body;
            v->n = len;
            v->type = (st & 1) ? SQ_TEXT : SQ_BLOB;
            if (v->type == SQ_TEXT && db->encoding != 1 && u8) {
                size_t got = u16_to_u8(body, len, db->encoding == 3, u8 + u8n, u8cap - u8n);
                v->p = u8 + u8n;
                v->n = got;
                u8n += got;
            }
            break;
        }
        body += len;
    }
    cb(rowid, cols, nc, ctx);
    free(u8);
}

// Assembles the payload of a cell (local part + overflow chain).
static unsigned char *payload(const sqlite_db *db, const unsigned char *p, const unsigned char *pend,
                              uint64_t psize, size_t *outn, int *alloc)
{
    uint32_t U = db->usable, X = U - 35;
    *alloc = 0;
    if (psize <= X) {
        if ((uint64_t)(pend - p) < psize) return NULL;
        *outn = (size_t)psize;
        return (unsigned char *)p;
    }
    uint32_t M = ((U - 12) * 32 / 255) - 23;
    uint64_t K = M + ((psize - M) % (U - 4));
    size_t local = (size_t)(K <= X ? K : M);
    if (psize > (uint64_t)db->pages * U + U || (size_t)(pend - p) < local + 4) return NULL;
    unsigned char *buf = (unsigned char *)malloc((size_t)psize);
    if (buf == NULL) return NULL;
    memcpy(buf, p, local);
    size_t got = local;
    uint32_t next = be32(p + local);
    unsigned hops = 0;
    while (got < psize && next && hops++ < MAX_OVERFLOW) {
        const unsigned char *op = page(db, next);
        if (op == NULL) break;
        size_t take = U - 4;
        if (take > psize - got) take = (size_t)(psize - got);
        memcpy(buf + got, op + 4, take);
        got += take;
        next = be32(op);
    }
    if (got < psize) { free(buf); return NULL; }
    *alloc = 1;
    *outn = (size_t)psize;
    return buf;
}

static long walk(const sqlite_db *db, uint32_t pgno, int depth, sqlite_row_cb cb, void *ctx)
{
    if (depth > MAX_DEPTH) return -1;
    const unsigned char *pg = page(db, pgno);
    if (pg == NULL) return -1;
    const unsigned char *hdr = pg + (pgno == 1 ? 100 : 0);
    const unsigned char *pend = pg + db->usable;
    uint8_t type = hdr[0];
    if (type != 0x0D && type != 0x05) return -1;
    uint16_t ncells = be16(hdr + 3);
    size_t hlen = type == 0x05 ? 12 : 8;
    const unsigned char *ptrs = hdr + hlen;
    if (ptrs + (size_t)ncells * 2 > pend) return -1;
    long total = 0;
    for (uint16_t i = 0; i < ncells; i++) {
        uint16_t off = be16(ptrs + 2 * i);
        if (off < 8 || off >= db->usable) continue;
        const unsigned char *c = pg + off;
        if (type == 0x05) {
            if (c + 4 > pend) continue;
            long r = walk(db, be32(c), depth + 1, cb, ctx);
            if (r > 0) total += r;
        } else {
            uint64_t psize, rowid;
            int a = varint(c, pend, &psize);
            if (a == 0) continue;
            int b = varint(c + a, pend, &rowid);
            if (b == 0) continue;
            size_t n;
            int alloc;
            unsigned char *rec = payload(db, c + a + b, pend, psize, &n, &alloc);
            if (rec == NULL) continue;
            decode_record(db, (int64_t)rowid, rec, n, cb, ctx);
            if (alloc) free(rec);
            total++;
        }
    }
    if (type == 0x05) {
        long r = walk(db, be32(hdr + 8), depth + 1, cb, ctx);      // right-most child
        if (r > 0) total += r;
    }
    return total;
}

long sqlite_scan(const sqlite_db *db, uint32_t root, sqlite_row_cb cb, void *ctx)
{
    return walk(db, root, 0, cb, ctx);
}

typedef struct { const char *name; uint32_t root; char sql[8192]; size_t sqln; } findt;

static void master_cb(int64_t rowid, const sqlite_val *c, int n, void *ctx)
{
    (void)rowid;
    findt *f = (findt *)ctx;
    // sqlite_master: type, name, tbl_name, rootpage, sql
    if (n < 4 || f->root || c[0].type != SQ_TEXT || c[1].type != SQ_TEXT || c[3].type != SQ_INT) return;
    size_t L = strlen(f->name);
    if (c[0].n == 5 && memcmp(c[0].p, "table", 5) == 0 && c[1].n == L && memcmp(c[1].p, f->name, L) == 0) {
        f->root = (uint32_t)c[3].i;
        if (n >= 5 && c[4].type == SQ_TEXT) {
            f->sqln = c[4].n < sizeof f->sql ? c[4].n : sizeof f->sql;
            memcpy(f->sql, c[4].p, f->sqln);
        }
    }
}

uint32_t sqlite_table_root(const sqlite_db *db, const char *table)
{
    static findt f;
    memset(&f, 0, sizeof f);
    f.name = table;
    walk(db, 1, 0, master_cb, &f);
    return f.root;
}

static int ieq_word(const char *p, size_t n, const char *w)
{
    size_t L = strlen(w);
    if (n != L) return 0;
    for (size_t i = 0; i < L; i++) {
        char a = p[i], b = w[i];
        if (a >= 'a' && a <= 'z') a = (char)(a - 32);
        if (a != b) return 0;
    }
    return 1;
}

int sqlite_parse_columns(const char *sql, size_t n, char names[][64], int max)
{
    // Body between the first '(' and its matching ')'.
    size_t i = 0;
    while (i < n && sql[i] != '(') i++;
    if (i >= n) return -1;
    i++;
    int count = 0;
    while (i < n && count < max) {
        // One definition, up to a top-level ',' or the closing ')'.
        while (i < n && (sql[i] == ' ' || sql[i] == '\t' || sql[i] == '\r' || sql[i] == '\n')) i++;
        size_t start = i;
        int depth = 0;
        char q = 0;
        while (i < n) {
            char c = sql[i];
            if (q) { if (c == q) q = 0; i++; continue; }
            if (c == '"' || c == '\'' || c == '`' || c == '[') { q = c == '[' ? ']' : c; i++; continue; }
            if (c == '(') depth++;
            else if (c == ')') { if (depth == 0) break; depth--; }
            else if (c == ',' && depth == 0) break;
            i++;
        }
        size_t end = i;
        // First token: the column name (possibly quoted).
        const char *p = sql + start;
        size_t len = 0;
        char nm[64];
        if (start < end && (*p == '"' || *p == '`' || *p == '[' || *p == '\'')) {
            char close = *p == '[' ? ']' : *p;
            size_t k = 1;
            while (start + k < end && p[k] != close && len + 1 < sizeof nm) nm[len++] = p[k++];
        } else {
            while (start + len < end && p[len] != ' ' && p[len] != '\t' && p[len] != '\n' && p[len] != '\r' &&
                   p[len] != '(' && len + 1 < sizeof nm) {
                nm[len] = p[len];
                len++;
            }
            if (ieq_word(p, len, "PRIMARY") || ieq_word(p, len, "UNIQUE") || ieq_word(p, len, "CHECK") ||
                    ieq_word(p, len, "FOREIGN") || ieq_word(p, len, "CONSTRAINT"))
                len = 0;                                    // a table constraint
        }
        if (len) {
            nm[len] = 0;
            memcpy(names[count], nm, len + 1);
            count++;
        }
        if (i >= n || sql[i] == ')') break;
        i++;                                                // the ','
    }
    return count;
}

int sqlite_columns(const sqlite_db *db, const char *table, char names[][64], int max)
{
    static findt f;
    memset(&f, 0, sizeof f);
    f.name = table;
    walk(db, 1, 0, master_cb, &f);
    if (f.root == 0 || f.sqln == 0) return -1;
    return sqlite_parse_columns(f.sql, f.sqln, names, max);
}
