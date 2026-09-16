#include <limits.h>
#include <string.h>
#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1

typedef struct State State;
typedef struct Session Session;
struct State {
    sqlite3 *db;
    Session *sessions;
    sqlite3_int64 sequence, opens, reopens, reads, bytes, active;
    int references;
};
struct Session {
    sqlite3_vtab_cursor base;
    State *state;
    Session *next;
    sqlite3_blob *blob;
    sqlite3_int64 id;
    int eof;
};
typedef struct { sqlite3_vtab base; State *state; } Table;

static void release(void *pointer) {
    State *state = pointer;
    if (--state->references == 0) sqlite3_free(state);
}

static void close_blob(Session *session) {
    if (session->blob) {
        sqlite3_blob_close(session->blob);
        session->blob = 0;
        --session->state->active;
    }
}

static int connect_table(sqlite3 *db, void *aux, int argc,
                         const char *const *argv, sqlite3_vtab **out, char **error) {
    (void)argc; (void)argv; (void)error;
    int rc = sqlite3_declare_vtab(db, "CREATE TABLE x(id INTEGER)");
    if (rc != SQLITE_OK) return rc;
    sqlite3_vtab_config(db, SQLITE_VTAB_DIRECTONLY);
    Table *table = sqlite3_malloc64(sizeof(*table));
    if (!table) return SQLITE_NOMEM;
    memset(table, 0, sizeof(*table));
    table->state = aux;
    ++table->state->references;
    *out = &table->base;
    return SQLITE_OK;
}

static int disconnect_table(sqlite3_vtab *base) {
    Table *table = (Table *)base;
    release(table->state);
    sqlite3_free(table);
    return SQLITE_OK;
}

static int best_index(sqlite3_vtab *table, sqlite3_index_info *info) {
    (void)table;
    info->estimatedCost = 1;
    info->estimatedRows = 1;
    return SQLITE_OK;
}

static int open_session(sqlite3_vtab *base, sqlite3_vtab_cursor **out) {
    State *state = ((Table *)base)->state;
    if (state->sequence == LLONG_MAX) return SQLITE_FULL;
    Session *session = sqlite3_malloc64(sizeof(*session));
    if (!session) return SQLITE_NOMEM;
    memset(session, 0, sizeof(*session));
    session->state = state;
    session->id = ++state->sequence;
    session->next = state->sessions;
    state->sessions = session;
    *out = &session->base;
    return SQLITE_OK;
}

static int close_session(sqlite3_vtab_cursor *base) {
    Session *session = (Session *)base;
    Session **link = &session->state->sessions;
    while (*link != session) link = &(*link)->next;
    *link = session->next;
    close_blob(session);
    sqlite3_free(session);
    return SQLITE_OK;
}

static int filter_session(sqlite3_vtab_cursor *base, int index, const char *text,
                          int argc, sqlite3_value **argv) {
    (void)index; (void)text; (void)argc; (void)argv;
    ((Session *)base)->eof = 0;
    return SQLITE_OK;
}
static int next_session(sqlite3_vtab_cursor *base) {
    Session *session = (Session *)base;
    session->eof = 1;
    close_blob(session);
    return SQLITE_OK;
}
static int eof_session(sqlite3_vtab_cursor *base) { return ((Session *)base)->eof; }
static int column_session(sqlite3_vtab_cursor *base, sqlite3_context *ctx, int column) {
    (void)column;
    sqlite3_result_int64(ctx, ((Session *)base)->id);
    return SQLITE_OK;
}
static int rowid_session(sqlite3_vtab_cursor *base, sqlite3_int64 *id) {
    *id = ((Session *)base)->id;
    return SQLITE_OK;
}

static const sqlite3_module sessions_module = {
    .iVersion = 3,
    .xConnect = connect_table, .xBestIndex = best_index,
    .xDisconnect = disconnect_table, .xOpen = open_session,
    .xClose = close_session, .xFilter = filter_session,
    .xNext = next_session, .xEof = eof_session,
    .xColumn = column_session, .xRowid = rowid_session,
};

static void read_blob(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    (void)argc;
    State *state = sqlite3_user_data(ctx);
    for (int i = 0; i < 4; ++i) {
        if (sqlite3_value_type(argv[i]) != SQLITE_INTEGER) {
            sqlite3_result_error(ctx, "integer arguments required", -1);
            return;
        }
    }
    sqlite3_int64 rowid = sqlite3_value_int64(argv[0]);
    sqlite3_int64 size = sqlite3_value_int64(argv[1]);
    sqlite3_int64 budget = sqlite3_value_int64(argv[2]);
    sqlite3_int64 id = sqlite3_value_int64(argv[3]);
    Session temporary = {.state = state};
    Session *session = &temporary;
    if (id) {
        session = state->sessions;
        while (session && session->id != id) session = session->next;
        if (!session || session->eof) {
            sqlite3_result_error(ctx, "inactive BLOB session", -1);
            return;
        }
    }
    if (size < 0 || size > INT_MAX || budget < size) {
        close_blob(session);
        sqlite3_result_error(ctx, "BLOB exceeds byte budget", -1);
        return;
    }

    int rc;
    if (session->blob) {
        ++state->reopens;
        rc = sqlite3_blob_reopen(session->blob, rowid);
    } else {
        ++state->opens;
        rc = sqlite3_blob_open(state->db, "main", "contract_state", "value",
                               rowid, 0, &session->blob);
        if (session->blob) ++state->active;
    }
    if (rc != SQLITE_OK) goto fail;
    if (sqlite3_blob_bytes(session->blob) != size) {
        close_blob(session);
        sqlite3_result_error(ctx, "BLOB length differs from metadata", -1);
        return;
    }
    /* A non-null allocation distinguishes an empty BLOB from SQL NULL. */
    void *buffer = sqlite3_malloc64(size ? (sqlite3_uint64)size : 1);
    if (!buffer) { rc = SQLITE_NOMEM; goto fail; }
    ++state->reads;
    rc = sqlite3_blob_read(session->blob, buffer, (int)size, 0);
    if (rc != SQLITE_OK) { sqlite3_free(buffer); goto fail; }
    state->bytes += size;
    sqlite3_result_blob64(ctx, buffer, (sqlite3_uint64)size, sqlite3_free);
    if (!id) close_blob(session);
    return;

fail:
    close_blob(session);
    sqlite3_result_error_code(ctx, rc);
}

static void stats(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    (void)argc;
    State *state = sqlite3_user_data(ctx);
    sqlite3_int64 counters[] = {state->opens, state->reopens, state->reads,
                               state->bytes, state->active};
    int index = sqlite3_value_int(argv[0]);
    if (index < 0 || index >= 5) sqlite3_result_error(ctx, "unknown counter", -1);
    else sqlite3_result_int64(ctx, counters[index]);
}

#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_kontorblob_init(sqlite3 *db, char **error,
                            const sqlite3_api_routines *api) {
    (void)error;
    SQLITE_EXTENSION_INIT2(api);
    State *state = sqlite3_malloc64(sizeof(*state));
    if (!state) return SQLITE_NOMEM;
    memset(state, 0, sizeof(*state));
    state->db = db;
    state->references = 2;
    int rc = sqlite3_create_module_v2(db, "kontor_blob_sessions", &sessions_module,
                                     state, release);
    if (rc != SQLITE_OK) { release(state); return rc; }
    ++state->references;
    rc = sqlite3_create_function_v2(db, "kontor_blob_read", 4,
                                    SQLITE_UTF8 | SQLITE_DIRECTONLY, state,
                                    read_blob, 0, 0, release);
    if (rc == SQLITE_OK) {
        ++state->references;
        rc = sqlite3_create_function_v2(db, "kontor_blob_stats", 1,
                                        SQLITE_UTF8 | SQLITE_DIRECTONLY, state,
                                        stats, 0, 0, release);
    }
    release(state);
    return rc;
}
