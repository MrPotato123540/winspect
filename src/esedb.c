// esedb - read-only ESE database reader (see esedb.h)

#include "esedb.h"

#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 16

static uint16_t rd16(const unsigned char *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const unsigned char *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t rd64(const unsigned char *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

int ese_open(ese_db *db, const unsigned char *d, size_t n)
{
    memset(db, 0, sizeof *db);
    if (n < 4096 || rd32(d + 4) != 0x89ABCDEF) return -1;
    db->d = d;
    db->n = n;
    db->page_size = rd32(d + 236);
    db->revision = rd32(d + 232);
    if (db->page_size != 2048 && db->page_size != 4096 && db->page_size != 8192 &&
            db->page_size != 16384 && db->page_size != 32768) return -1;
    db->hdr = db->page_size >= 16384 ? 80 : 40;
    return 0;
}

static const unsigned char *page(const ese_db *db, uint32_t pgno)
{
    size_t off = ((size_t)pgno + 1) * db->page_size;
    if (pgno == 0 || off + db->page_size > db->n) return NULL;
    return db->d + off;
}

typedef struct {
    const unsigned char *key, *data;
    size_t keylen, datalen;
    int flags;
} entry;

// Tag i of a page -> its entry (key and data split). 0 on success.
static int get_entry(const ese_db *db, const unsigned char *pg, unsigned i, entry *e)
{
    uint16_t ntags = rd16(pg + 34);
    if (i >= ntags) return -1;
    const unsigned char *tag = pg + db->page_size - 4 * (i + 1);
    size_t size, off;
    int flags;
    if (db->page_size >= 16384) {
        size = rd16(tag) & 0x7FFF;
        off = rd16(tag + 2) & 0x7FFF;
        flags = 0;                                      // in the value's first bytes (below)
    } else {
        size = rd16(tag) & 0x1FFF;
        off = rd16(tag + 2) & 0x1FFF;
        flags = rd16(tag + 2) >> 13;
    }
    size_t base = db->hdr;
    if (base + off + size > db->page_size - 4u * ntags || size == 0) return -1;
    const unsigned char *v = pg + base + off;
    if (db->page_size >= 16384 && size >= 2) flags = rd16(v) >> 13;
    memset(e, 0, sizeof *e);
    e->flags = flags;
    if (i == 0) {                                       // page "external" header
        e->data = v;
        e->datalen = size;
        return 0;
    }
    size_t p = 0;
    if (flags & 0x4) {                                  // common key size (prefix shared with tag 0)
        if (size < 2) return -1;
        p += 2;
    }
    if (p + 2 > size) return -1;
    size_t kl = rd16(v + p) & (db->page_size >= 16384 ? 0x1FFF : 0xFFFF);
    p += 2;
    if (p + kl > size) return -1;
    e->key = v + p;
    e->keylen = kl;
    e->data = v + p + kl;
    e->datalen = size - p - kl;
    return 0;
}

typedef void (*leaf_cb)(const entry *e, void *ctx);

static long walk(const ese_db *db, uint32_t pgno, int depth, leaf_cb cb, void *ctx)
{
    if (depth > MAX_DEPTH) return -1;
    const unsigned char *pg = page(db, pgno);
    if (pg == NULL) return -1;
    uint32_t flags = rd32(pg + 36);
    uint16_t ntags = rd16(pg + 34);
    if (flags & 0x8) return 0;                          // empty page
    long total = 0;
    for (unsigned i = 1; i < ntags; i++) {
        entry e;
        if (get_entry(db, pg, i, &e) != 0) continue;
        if (e.flags & 0x2) continue;                    // deleted (defunct) entry
        if (flags & 0x2) {                              // leaf
            cb(&e, ctx);
            total++;
        } else {                                        // branch: data = child page. (The
                                                        // "parent" flag is not always set on
                                                        // a root that is a branch - SRUDB.dat.)
            if (e.datalen < 4) continue;
            long r = walk(db, rd32(e.data + e.datalen - 4), depth + 1, cb, ctx);
            if (r > 0) total += r;
        }
    }
    return total;
}

// ---- records -----------------------------------------------------------------------

struct ese_row {
    const ese_db *db;
    const ese_table *t;
    const unsigned char *rec;
    size_t len;
    unsigned char *lvbuf;       // long values reassembled for this row
};

static int fixed_size(uint32_t type, uint32_t size)
{
    switch (type) {
    case ESE_BIT: case ESE_UBYTE: return 1;
    case ESE_SHORT: case ESE_USHORT: return 2;
    case ESE_LONG: case ESE_ULONG: case ESE_FLOAT: return 4;
    case ESE_CURRENCY: case ESE_DOUBLE: case ESE_DATETIME: case ESE_LONGLONG: return 8;
    case ESE_GUID: return 16;
    default: return (int)size;                          // fixed-size binary / text
    }
}

static const ese_column *col_by_name(const ese_table *t, const char *name)
{
    for (int i = 0; i < t->ncols; i++) if (strcmp(t->cols[i].name, name) == 0) return &t->cols[i];
    return NULL;
}

// Long value by id: chunks of the table's LV tree whose key is (LID, offset).
typedef struct { uint32_t lid; unsigned char *buf; size_t cap, len; } lvctx;

static void lv_cb(const entry *e, void *vctx)
{
    lvctx *x = (lvctx *)vctx;
    if (e->keylen != 8) return;                         // the 4-byte key is the LV header
    uint32_t lid = ((uint32_t)e->key[0] << 24) | ((uint32_t)e->key[1] << 16) | ((uint32_t)e->key[2] << 8) | e->key[3];
    uint32_t off = ((uint32_t)e->key[4] << 24) | ((uint32_t)e->key[5] << 16) | ((uint32_t)e->key[6] << 8) | e->key[7];
    if (lid != x->lid || off > (1u << 24)) return;
    if (off + e->datalen > x->cap) {
        size_t nc = off + e->datalen + 4096;
        unsigned char *nb = (unsigned char *)realloc(x->buf, nc);
        if (nb == NULL) return;
        x->buf = nb;
        x->cap = nc;
    }
    memcpy(x->buf + off, e->data, e->datalen);
    if (off + e->datalen > x->len) x->len = off + e->datalen;
}

int ese_get(const ese_row *row, const char *name, ese_val *v)
{
    memset(v, 0, sizeof *v);
    const ese_column *c = col_by_name(row->t, name);
    const unsigned char *r = row->rec;
    size_t n = row->len;
    if (c == NULL || n < 4) return 0;
    uint8_t last_fixed = r[0], last_var = r[1];
    uint16_t var_off = rd16(r + 2);
    if (var_off > n) return 0;
    if (c->id < 128) {                                  // fixed
        if (c->id > last_fixed) return 0;
        size_t off = 4;
        for (uint32_t id = 1; id < c->id; id++) {
            const ese_column *o = NULL;
            for (int i = 0; i < row->t->ncols; i++) if (row->t->cols[i].id == id) o = &row->t->cols[i];
            if (o == NULL) return 0;                    // unknown layout
            off += (size_t)fixed_size(o->type, o->size);
        }
        size_t sz = (size_t)fixed_size(c->type, c->size);
        if (off + sz > var_off) return 0;
        // Null bitmap right after the fixed data: bit (id - 1) set = NULL.
        size_t fixed_end = 4;
        for (uint32_t id = 1; id <= last_fixed; id++) {
            const ese_column *o = NULL;
            for (int i = 0; i < row->t->ncols; i++) if (row->t->cols[i].id == id) o = &row->t->cols[i];
            if (o) fixed_end += (size_t)fixed_size(o->type, o->size);
        }
        size_t bm = fixed_end + (c->id - 1) / 8;
        if (bm < var_off && (r[bm] >> ((c->id - 1) % 8)) & 1) return 0;
        v->present = 1;
        v->data = r + off;
        v->len = sz;
        return 1;
    }
    size_t nvar = last_var >= 128 ? (size_t)(last_var - 127) : 0;
    size_t var_data = (size_t)var_off + nvar * 2;
    if (var_data > n) return 0;
    if (c->id < 256) {                                  // variable
        if (c->id > last_var) return 0;
        size_t idx = c->id - 128;
        uint16_t end = rd16(r + var_off + 2 * idx);
        if (end & 0x8000) return 0;
        size_t start = idx ? (rd16(r + var_off + 2 * (idx - 1)) & 0x7FFF) : 0;
        end &= 0x7FFF;
        if (start > end || var_data + end > n) return 0;
        v->present = 1;
        v->data = r + var_data + start;
        v->len = end - start;
        return 1;
    }
    // Tagged: after the last variable column's data.
    size_t tag = var_data + (nvar ? (rd16(r + var_off + 2 * (nvar - 1)) & 0x7FFF) : 0);
    if (tag + 4 > n) return 0;
    size_t first = rd16(r + tag + 2) & 0x3FFF;
    size_t ntag = first / 4;
    for (size_t i = 0; i < ntag && tag + 4 * i + 4 <= n; i++) {
        uint16_t id = rd16(r + tag + 4 * i), ov = rd16(r + tag + 4 * i + 2);
        if (id != c->id) continue;
        size_t off = ov & 0x3FFF;
        size_t end = (i + 1 < ntag) ? (rd16(r + tag + 4 * (i + 1) + 2) & 0x3FFF) : n - tag;
        if (off > end || tag + end > n) return 0;
        const unsigned char *p = r + tag + off;
        size_t len = end - off;
        int tflags = 0;
        if ((ov & 0x4000) || row->db->revision >= 0x11) {  // a flags byte leads the value
            if (len < 1) return 0;
            tflags = p[0];
            p++;
            len--;
        }
        if (tflags & 0x02) v->compressed = 1;
        if (tflags & 0x04) {                            // stored in the long-value tree
            if (len < 4 || row->t->lv_fdp == 0) return 0;
            lvctx x = { rd32(p), NULL, 0, 0 };
            walk(row->db, row->t->lv_fdp, 0, lv_cb, &x);
            if (x.buf == NULL) return 0;
            free(((ese_row *)row)->lvbuf);
            ((ese_row *)row)->lvbuf = x.buf;
            p = x.buf;
            len = x.len;
        }
        v->present = 1;
        v->data = p;
        v->len = len;
        return 1;
    }
    return 0;
}

int64_t ese_int(const ese_row *row, const char *col)
{
    ese_val v;
    if (!ese_get(row, col, &v)) return 0;
    switch (v.len) {
    case 1: return v.data[0];
    case 2: return (int16_t)rd16(v.data);
    case 4: return (int32_t)rd32(v.data);
    case 8: return (int64_t)rd64(v.data);
    default: return 0;
    }
}

double ese_double(const ese_row *row, const char *col)
{
    ese_val v;
    double d = 0;
    if (ese_get(row, col, &v) && v.len == 8) {
        uint64_t bits = rd64(v.data);
        memcpy(&d, &bits, 8);
    }
    return d;
}

// ---- catalog -------------------------------------------------------------------------

typedef struct { ese_table *t; int found_table; } catctx;

static const ese_table catalog_schema = {
    "MSysObjects", 2, 4, 0,
    { { 1, ESE_LONG, 4, 0, "ObjidTable" }, { 2, ESE_SHORT, 2, 0, "Type" }, { 3, ESE_LONG, 4, 0, "Id" },
      { 4, ESE_LONG, 4, 0, "ColtypOrPgnoFDP" }, { 5, ESE_LONG, 4, 0, "SpaceUsage" }, { 6, ESE_LONG, 4, 0, "Flags" },
      { 7, ESE_LONG, 4, 0, "PagesOrLocale" }, { 8, ESE_BIT, 1, 0, "RootFlag" }, { 9, ESE_SHORT, 2, 0, "RecordOffset" },
      { 10, ESE_LONG, 4, 0, "LCMapFlags" }, { 11, ESE_USHORT, 2, 0, "KeyMost" }, { 12, ESE_LONG, 4, 0, "LVChunkMax" },
      { 128, ESE_TEXT, 255, 0, "Name" } },
    13
};

static void cat_cb(const entry *e, void *vctx)
{
    catctx *x = (catctx *)vctx;
    ese_row row = { NULL, &catalog_schema, e->data, e->datalen, NULL };
    static ese_db dummy;
    row.db = &dummy;
    ese_val name;
    if (!ese_get(&row, "Name", &name) || name.len == 0 || name.len >= 64) return;
    int type = (int)ese_int(&row, "Type");
    uint32_t objid = (uint32_t)ese_int(&row, "ObjidTable");
    char nm[64];
    memcpy(nm, name.data, name.len);
    nm[name.len] = 0;
    ese_table *t = x->t;
    if (type == 1 && strcmp(nm, t->name) == 0) {
        t->objid = objid;
        t->fdp = (uint32_t)ese_int(&row, "ColtypOrPgnoFDP");
        x->found_table = 1;
    } else if (x->found_table && objid == t->objid) {
        if (type == 2 && t->ncols < 256) {
            ese_column *c = &t->cols[t->ncols++];
            c->id = (uint32_t)ese_int(&row, "Id");
            c->type = (uint32_t)ese_int(&row, "ColtypOrPgnoFDP");
            c->size = (uint32_t)ese_int(&row, "SpaceUsage");
            c->codepage = (uint32_t)ese_int(&row, "PagesOrLocale");
            memcpy(c->name, nm, strlen(nm) + 1);
        } else if (type == 4) {
            t->lv_fdp = (uint32_t)ese_int(&row, "ColtypOrPgnoFDP");
        }
    }
}

int ese_table_open(const ese_db *db, const char *name, ese_table *t)
{
    memset(t, 0, sizeof *t);
    size_t L = strlen(name);
    if (L >= sizeof t->name) return -1;
    memcpy(t->name, name, L + 1);
    catctx x = { t, 0 };
    // The catalog's entries are ordered by (ObjidTable, Type, ...), so a
    // table's row comes before its columns and long-value tree.
    walk(db, 4, 0, cat_cb, &x);
    return x.found_table && t->fdp ? 0 : -1;
}

typedef struct { const ese_db *db; const ese_table *t; ese_row_cb cb; void *ctx; } rowctx;

static void row_cb(const entry *e, void *vctx)
{
    rowctx *x = (rowctx *)vctx;
    ese_row row = { x->db, x->t, e->data, e->datalen, NULL };
    x->cb(&row, x->ctx);
    free(row.lvbuf);
}

long ese_rows(const ese_db *db, const ese_table *t, ese_row_cb cb, void *ctx)
{
    rowctx x = { db, t, cb, ctx };
    return walk(db, t->fdp, 0, row_cb, &x);
}
