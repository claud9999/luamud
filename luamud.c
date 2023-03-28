#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h> /* malloc/free */
#include <string.h> /* memset */
#include <stdbool.h> /* bool, duh */
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <regex.h>
#include <stdarg.h>

#define MUD_MARKER 0xBEADDEEF

char inbuf[1024];

typedef int obj_id_t;

typedef enum {
    SERVER_RUNNING,
    SERVER_SHUTDOWN
} server_state_t;

server_state_t server_state = SERVER_RUNNING;

typedef struct {
    int marker;
    obj_id_t id, par, loc, own;
} mud_obj_t;

typedef struct {
    SSL *ssl;
    int clientsocket;
    obj_id_t obj_id;
    sqlite3 *db;
} connection_t;

static void dumpstack (lua_State *L, const char *pfx) {
  int top=lua_gettop(L);
  for (int i=1; i <= top; i++) {
    printf("%s%d\t%s\t", pfx, i, luaL_typename(L,i));
    switch (lua_type(L, i)) {
      case LUA_TNUMBER: printf("%g\n",lua_tonumber(L,i)); break;
      case LUA_TSTRING: printf("%s\n",lua_tostring(L,i)); break;
      case LUA_TBOOLEAN: printf("%s\n", (lua_toboolean(L, i) ? "true" : "false")); break;
      case LUA_TNIL: printf("%s\n", "nil"); break;
      case LUA_TTABLE:
        lua_pushnil(L);
        while(lua_next(L, i) != 0) {
            printf("%s%s - %s\n", pfx, lua_typename(L, lua_type(L, -2)), lua_typename(L, lua_type(L, -1)));
            lua_pop(L, 1);
        }
      default:
        printf("%p\n",lua_topointer(L,i));
        break;
    }
  }
}

#ifdef DEBUG
#define DBG() { printf("%s\n", __func__); }
#else /* DEBUG */
#define DBG()
#endif /* DEBUG */

int mud_err(lua_State *lua_state, const char *msg) {
    lua_pushstring(lua_state, msg);
    lua_error(lua_state);
    return 1;
}

int sql_err(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    return 1;
}

typedef struct {
    uint8_t *buf;
    size_t pos, sz;
} mud_prop_fnbuf_t;

// TODO: to re-write using blob writing.
int mud_prop_fnwriter(lua_State *lua_state, const void *p, size_t sz, void *ud) { DBG();
    mud_prop_fnbuf_t *b = ud;
    if(sz + b->pos >= b->sz) return 1;
    memcpy(b->buf + b->pos, p, sz);
    b->pos += sz;
    return 0;
}

const char *mud_prop_fnreader(lua_State *lua_state, void *data, size_t *sz) { DBG();
    mud_prop_fnbuf_t *b = data;
    *sz = b->sz;
    return (const char *)b->buf;
}

/* (obj name val - ) returns 0 on success */
int mud_obj_set(lua_State *lua_state) { DBG();
    connection_t *connection = *((connection_t **)lua_getextraspace(lua_state));
    mud_obj_t *obj = NULL;
    const char *propname = NULL;
    const char *propval = NULL;
    sqlite3_stmt *stmt = NULL;
    int sqlite3_rc = 0;
    int proptype = 0;

    if(lua_gettop(lua_state) < 3 || !lua_isstring(lua_state, -2)) return mud_err(lua_state, "Invalid call.");

    proptype = lua_type(lua_state, -1);
    propname = lua_tostring(lua_state, -2);
    obj = lua_touserdata(lua_state, -3);

    if(obj->marker != MUD_MARKER) return mud_err(lua_state, "Invalid object.");

    if(sqlite3_prepare_v3(connection->db, "delete from mud_prop where obj_id = ? and name = ?", -1, 0, &stmt, NULL) != SQLITE_OK) return mud_err(lua_state, "Unable to prepare query.");

    if(sqlite3_bind_int(stmt, 1, obj->id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return sql_err("Unable to bind obj id.");
    }

    if(sqlite3_bind_text(stmt, 2, propname, -1, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return sql_err("Unable to bind name.");
    }

    if(sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return sql_err("Unable to step query.");
    }

    sqlite3_finalize(stmt);

    if (proptype == LUA_TNIL) {
        lua_pop(lua_state, 3);
        return 1;
    }

    if(sqlite3_prepare_v3(connection->db, "insert into mud_prop(obj_id, name, type, val) values (?, ?, ?, ?)", -1, 0, &stmt, NULL) != SQLITE_OK)
        return sql_err("Unable to prepare query.");

    if(sqlite3_bind_int(stmt, 1, obj->id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return sql_err("Unable to bind ID.");
    }

    if(sqlite3_bind_text(stmt, 2, propname, -1, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return sql_err("Unable to bind name.");
    }

    if(sqlite3_bind_int(stmt, 3, proptype) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return sql_err("Unable to bind proptype.");
    }

    switch (proptype) {
        case LUA_TBOOLEAN:
        case LUA_TNUMBER: {
            int propval = lua_tonumber(lua_state, -1);
            if(sqlite3_bind_int(stmt, 4, propval) != SQLITE_OK) sql_err("Unable to bind value.");
            break;
        }
        case LUA_TSTRING: {
            const char *propval = lua_tostring(lua_state, -1);
            if(sqlite3_bind_text(stmt, 4, propval, -1, NULL) != SQLITE_OK) sql_err("Unable to bind value.");
            break;
        }
        case LUA_TFUNCTION: {
            uint8_t buf[1024]; // do we want dynamic?
            mud_prop_fnbuf_t b = {
                .buf = buf,
                .sz = sizeof(buf),
                .pos = 0
            };

            lua_dump(lua_state, mud_prop_fnwriter, &b, 0);
            if(sqlite3_bind_blob(stmt, 4, b.buf, b.pos, NULL) != SQLITE_OK) sql_err("Unable to bind value.");
            break;
        }
        default:
            sqlite3_finalize(stmt);
            return mud_err(lua_state, "Invalid type.");
    }

    lua_pop(lua_state, 3);

    if(sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return sql_err("Odd return from step.");
    }

    sqlite3_finalize(stmt);

    return 0;
}

// TODO: parameterize which field, possibly macro-ize?
/* returns 0 on failure, otherwise returns object id */
obj_id_t mud_get_parent_id(sqlite3 *db, obj_id_t obj_id) { DBG();
    sqlite3_stmt *stmt = NULL;

    if(sqlite3_prepare_v3(db, "select par_id from mud_obj where id = ?", -1, 0, &stmt, NULL) != SQLITE_OK)
        return !sql_err("Unable to prepare query.");

    if(sqlite3_bind_int(stmt, 1, obj_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return !sql_err("Unable to bind ID.");
    }

    switch(sqlite3_step(stmt)) {
        case SQLITE_DONE:
            sqlite3_finalize(stmt);
            return 0;
        case SQLITE_ROW: {
            obj_id_t par_id = sqlite3_column_int(stmt, 1);
            sqlite3_finalize(stmt);
            return par_id;
        }
        default:
            sqlite3_finalize(stmt);
            return 0;
    }
}

/* returns 0 on failure, otherwise returns object id */
obj_id_t mud_get_location_id(sqlite3 *db, obj_id_t obj_id) { DBG();
    sqlite3_stmt *stmt = NULL;

    if(sqlite3_prepare_v3(db, "select loc_id from mud_obj where id = ?", -1, 0, &stmt, NULL) != SQLITE_OK)
        return !sql_err("Unable to prepare query.");

    if(sqlite3_bind_int(stmt, 1, obj_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return !sql_err("Unable to bind ID.");
    }

    switch(sqlite3_step(stmt)) {
        case SQLITE_DONE:
            sqlite3_finalize(stmt);
            return 0;
        case SQLITE_ROW: {
            obj_id_t par_id = sqlite3_column_int(stmt, 1);
            sqlite3_finalize(stmt);
            return par_id;
        }
        default:
            sqlite3_finalize(stmt);
            return 0;
    }
}

/* returns 0 when it finds the property */
int mud_obj_get_recurse(lua_State *lua_state, sqlite3 *db, int obj_id, const char *name) { DBG();
    if (!obj_id) return 1;

    sqlite3_stmt *stmt = NULL;

    if(sqlite3_prepare_v3(db, "select type, val from mud_prop where obj_id = ? and name = ?", -1, 0, &stmt, NULL) != SQLITE_OK)
        return sql_err("Unable to prepare query.");

    if(sqlite3_bind_int(stmt, 1, obj_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return sql_err("Unable to bind ID.");
    }

    if(sqlite3_bind_text(stmt, 2, name, -1, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return sql_err("Unable to bind name.");
    }

    switch(sqlite3_step(stmt)) {
        case SQLITE_DONE:
            sqlite3_finalize(stmt);
            return mud_obj_get_recurse(lua_state, db, mud_get_parent_id(db, obj_id), name);
        case SQLITE_ROW: {
            int proptype = sqlite3_column_int(stmt, 0);
            switch(proptype) {
                case LUA_TNUMBER: {
                    lua_pushnumber(lua_state, sqlite3_column_int(stmt, 1));
                    sqlite3_finalize(stmt);
                    return 0;
                }
                case LUA_TSTRING: {
                    lua_pushstring(lua_state, (const char *)sqlite3_column_text(stmt, 1));
                    sqlite3_finalize(stmt);
                    return 0;
                }
                case LUA_TFUNCTION: {
                    uint8_t *d = (uint8_t *)sqlite3_column_blob(stmt, 1);
                    mud_prop_fnbuf_t b = {
                        .buf = (uint8_t *)sqlite3_column_blob(stmt, 1),
                        .pos = 0,
                        .sz = sqlite3_column_bytes(stmt, 1)
                    };
                    lua_load(lua_state, mud_prop_fnreader, &b, "mudfn", "b");
                    sqlite3_finalize(stmt);
                    return 0;
                }
                default:
                    sqlite3_finalize(stmt);
                    return mud_err(lua_state, "Invalid type of property.");
            }
            break;
        }
        default:
            sqlite3_finalize(stmt);
            return mud_err(lua_state, "Invalid datatype.");
    }

    return 1;
}

int mud_obj_get(lua_State *lua_state) { DBG();
    connection_t *connection = *((connection_t **)lua_getextraspace(lua_state));
    mud_obj_t *obj = NULL;
    const char *propname = NULL;
    sqlite3_stmt *stmt = NULL;
    int sqlite3_rc = 0;

    if(lua_gettop(lua_state) < 2 || !lua_isstring(lua_state, -1)) return mud_err(lua_state, "Invalid call.");
    propname = lua_tostring(lua_state, -1); lua_pop(lua_state, 1);
    obj = lua_touserdata(lua_state, -1); lua_pop(lua_state, 1);

    if (obj->marker != MUD_MARKER) return mud_err(lua_state, "Invalid object.");

    return !mud_obj_get_recurse(lua_state, connection->db, obj->id, propname);
}

int push_mud_obj(lua_State *lua_state, int id, int par_id, int loc_id) { DBG();
    mud_obj_t *mud_obj = malloc(sizeof(*mud_obj));
    memset(mud_obj, 0, sizeof(*mud_obj));
    mud_obj->marker = MUD_MARKER;
    mud_obj->id = id;
    mud_obj->par = par_id;
    mud_obj->loc = loc_id;

    lua_pushlightuserdata(lua_state, mud_obj);
    lua_createtable(lua_state, 0, 1); /* narr, nrec */

    lua_pushliteral(lua_state, "__index");
    lua_pushcfunction(lua_state, mud_obj_get);
    lua_rawset(lua_state, -3);

    lua_pushliteral(lua_state, "__newindex");
    lua_pushcfunction(lua_state, mud_obj_set);
    lua_rawset(lua_state, -3);

    lua_setmetatable(lua_state, -2);

    return 1;
}

int create_mud_obj(lua_State *lua_state, connection_t *connection) { DBG();
    sqlite3_stmt *stmt = NULL;
    int id = 0;

    if(sqlite3_prepare_v3(connection->db, "insert into mud_obj(par_id, loc_id, own_id) values(0, 0, 0)", -1, 0, &stmt, NULL) != SQLITE_OK)
        return mud_err(lua_state, "Unable to prepare insert.");

    if(sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to create obj.");
    }
    sqlite3_finalize(stmt);

    if(sqlite3_prepare_v3(connection->db, "select last_insert_rowid()", -1, 0, &stmt, NULL) != SQLITE_OK)
        return mud_err(lua_state, "Unable to prepare query.");

    if(sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to step select.");
    }

    id = sqlite3_column_int(stmt, 1);

    sqlite3_finalize(stmt);

    return push_mud_obj(lua_state, id, 0, 0);
}

int load_mud_obj(lua_State *lua_state, connection_t *connection, int obj_id) { DBG();
    sqlite3_stmt *stmt = NULL;

    if(sqlite3_prepare_v3(connection->db, "select par_id, loc_id from mud_obj where id = ?", -1, 0, &stmt, NULL) != SQLITE_OK)
        return mud_err(lua_state, "Unable to prepare query.");

    if(sqlite3_bind_int(stmt, 1, obj_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to bind ID.");
    }

    if(sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Invalid object ID.");
    }

    push_mud_obj(lua_state,
        obj_id,
        sqlite3_column_int(stmt, 0),
        sqlite3_column_int(stmt, 1)
    );

    sqlite3_finalize(stmt);

    return 1;
}

int mud_obj(lua_State *lua_state) { DBG();
    connection_t *connection = *((connection_t **)lua_getextraspace(lua_state));
    sqlite3_stmt *stmt = NULL;
    int sqlite3_rc = 0;
    int r = 0;
    int obj_id = 0;
    mud_obj_t *mud_obj = NULL;

    if (lua_gettop(lua_state) < 1)
        return create_mud_obj(lua_state, connection);

    if (!lua_isnumber(lua_state, 1))
        return mud_err(lua_state, "Need object ID");

    obj_id = lua_tointeger(lua_state, 1);
    lua_pop(lua_state, 1);

    return load_mud_obj(lua_state, connection, obj_id);
}

int main_cont(lua_State *lua_state, int status, lua_KContext ctx) { DBG();
    connection_t *connection = (connection_t *)ctx;
    sqlite3_close(connection->db);
    return 0;
}

int create_socket(int port) { DBG();
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX *create_context() { DBG();
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) { DBG();
   /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int conn_send(connection_t *connection, const char *fmt, ...) { DBG();
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    size_t sz = vsnprintf(buf, sizeof(buf), fmt, ap);
    return SSL_write(connection->ssl, buf, sz);
}

void command_who(connection_t *connection) { DBG();
    sqlite3_stmt *stmt = NULL;

    if(sqlite3_prepare_v3(connection->db, "select obj_id, username from mud_auth where connected = 1", -1, 0, &stmt, NULL) != SQLITE_OK) {
        sql_err("Unable to prepare who query.\n");
        return;
    }

    while(sqlite3_step(stmt) == SQLITE_ROW) {
        int obj_id = sqlite3_column_int(stmt, 0);
        const unsigned char *username = sqlite3_column_text(stmt, 1);
        if (conn_send(connection, "%d %s\n", obj_id, username) < 0) return;
    }
    sqlite3_finalize(stmt);
}

void mark_connected(connection_t *connection, bool isconnected) { DBG();
    sqlite3_stmt *stmt = NULL;

    if(sqlite3_prepare_v3(connection->db, "update mud_auth set connected = ? where obj_id = ?", -1, 0, &stmt, NULL) != SQLITE_OK) {
        sql_err("Error: unable to prepare query.\n");
        return;
    }

    if (sqlite3_bind_int(stmt, 1, connection->obj_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sql_err("Unable to bind obj id.");
        return;
    }

    if (sqlite3_bind_int(stmt, 2, isconnected ? 1 : 0) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sql_err("Unable to bind connected flag.");
        return;
    }

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

bool str_is(const char *a, const char *b) {
    if(!a || !b) return false;
    if(strlen(a) != strlen(b)) return false;
    return strcmp(a, b) == 0;
}

typedef struct {
    char *buf;
    size_t buf_len;
    SSL *ssl;
    int state;
} pgm_reader_t;

const char *pgm_reader(lua_State *lua_state, void *data, size_t *size) { DBG();
    pgm_reader_t *r = data;
    if(r->state == 0) {
        SSL_write(r->ssl, ". to end\n", 9);
        r->state = 1;
    }
    SSL_write(r->ssl, ">> ", 3);
    *size = SSL_read(r->ssl, r->buf, r->buf_len - 1);
    r->buf[*size] = '\0';
    if (str_is(r->buf, ".\n")) { *size = 0; }
    if(!*size) return NULL;
    return r->buf;
}

int lua_print(lua_State *lua_state) { DBG();
    connection_t *connection = *((connection_t **)lua_getextraspace(lua_state));
    if (lua_gettop(lua_state) < 1 || !lua_isstring(lua_state, 1)) return 1; // TODO: error handling
    const char *msg = lua_tostring(lua_state, 1);
    SSL_write(connection->ssl, msg, strlen(msg));
    lua_pop(lua_state, 1);
    return 1;
}

int lua_location(lua_State *lua_state) { DBG();
    connection_t *connection = *((connection_t **)lua_getextraspace(lua_state));
    if (lua_gettop(lua_state) != 1 || !lua_isuserdata(lua_state, 1)) return 1; // TODO: error handling
    mud_obj_t *obj = lua_touserdata(lua_state, 1);
    lua_pop(lua_state, 1);
    load_mud_obj(lua_state, connection, obj->loc);
    dumpstack(lua_state, "FOOBAR 1:");
    return 1;
}

int cmdloop(connection_t *connection) { DBG();
    lua_State *lua_state = luaL_newstate();
    void **es = (void **)lua_getextraspace(lua_state);
    *es = connection;

    lua_pushcfunction(lua_state, lua_print);
    lua_setglobal(lua_state, "print");

    lua_pushcfunction(lua_state, lua_location);
    lua_setglobal(lua_state, "location");

    while(1) {
        size_t readbytes = SSL_read(connection->ssl, inbuf, sizeof(inbuf) - 1);
        if (readbytes <= 0) break;
        inbuf[readbytes] = '\0';

        char *tok_sav = NULL;
        const char *cmd = strtok_r(inbuf, " \n", &tok_sav);
        if(!cmd) continue;

        if(str_is(cmd, "@quit")) break;
        if(str_is(cmd, "@shutdown")) break;
        if(str_is(cmd, "@who")) { command_who(connection); continue; }
        if(str_is(cmd, "@pgm")) {
            int obj_id = atoi(strtok_r(NULL, " \n", &tok_sav));
            load_mud_obj(lua_state, connection, obj_id);
            char *method_name = strdup(strtok_r(NULL, " \n", &tok_sav));
            lua_pushstring(lua_state, method_name);
            memset(inbuf, 0, sizeof(inbuf));
            pgm_reader_t r = {
                .buf = inbuf,
                .buf_len = sizeof(inbuf),
                .ssl = connection->ssl,
                .state = 0
            };
            if (obj_id || method_name) {
                lua_load(lua_state, pgm_reader, &r, method_name, "t");
                dumpstack(lua_state, "");
            }
            mud_obj_set(lua_state);
            free(method_name);
            continue;
        }

        load_mud_obj(lua_state, connection, connection->obj_id);
        lua_pushstring(lua_state, inbuf); // TODO tokenize
        mud_obj_get(lua_state);

        if(lua_isinteger(lua_state, 1)) {
            conn_send(connection, "%d\n", lua_tointeger(lua_state, 1));
            lua_pop(lua_state, 1);
        }
        else if(lua_isstring(lua_state, 1)) {
            conn_send(connection, "%s\n", lua_tostring(lua_state, 1));
            lua_pop(lua_state, 1);
        }
        else if(lua_isfunction(lua_state, 1)) {
            load_mud_obj(lua_state, connection, connection->obj_id);
            lua_setglobal(lua_state, "self");
            lua_pcall(lua_state, 0, 0, 0);
        }
    }
    lua_close(lua_state);

    return 0;
}

void *connected(void *arg) { DBG();
    connection_t *connection = (connection_t *)arg;
    sqlite3_stmt *stmt = NULL;
    size_t readbytes = 0;

    regex_t preg;
    regmatch_t matches[3];
    regcomp(&preg, "connect ([^ ]*) (.*)", REG_EXTENDED);
    while(!connection->obj_id) { /* unauthenticated */
        if (conn_send(connection, "Connect: ") < 0) return NULL;

        readbytes = SSL_read(connection->ssl, inbuf, sizeof(inbuf));
        if (readbytes <= 0) break;
        inbuf[readbytes - 1] = '\0'; /* remove EOL, or mark end of buf */
        if(regexec(&preg, inbuf, 3, matches, 0) == 0) {
            char *username = inbuf + matches[1].rm_so; inbuf[matches[1].rm_eo] = '\0';

            if(sqlite3_prepare_v3(connection->db, "select obj_id, password, password_salt from mud_auth where username = ?", -1, 0, &stmt, NULL) != SQLITE_OK) {
                sql_err("Error: unable to prepare query.\n");
                return NULL;
            }

            if (sqlite3_bind_text(stmt, 1, username, -1, NULL) != SQLITE_OK) {
                sqlite3_finalize(stmt);
                sql_err("Unable to bind user/pass.");
                return NULL;
            } else if(sqlite3_step(stmt) != SQLITE_ROW) {
                if(conn_send(connection, "Invalid username/password.\n")) return NULL;
                sqlite3_finalize(stmt);
                continue;
            }

            int obj_id = sqlite3_column_int(stmt, 0);
            const unsigned char *password = sqlite3_column_text(stmt, 1), *password_salt = sqlite3_column_text(stmt, 2);

            EVP_MD_CTX *mdctx;
            const EVP_MD *md;
            unsigned char md_value[EVP_MAX_MD_SIZE];
            unsigned int md_len;

            OpenSSL_add_all_digests();

            mdctx = EVP_MD_CTX_create();
            EVP_DigestInit(mdctx, EVP_sha1());
            EVP_DigestUpdate(mdctx, password_salt, strlen((const char *)password_salt));
            EVP_DigestUpdate(mdctx, inbuf + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
            EVP_DigestFinal(mdctx, md_value, &md_len);
            EVP_MD_CTX_destroy(mdctx);

            BIO *bio_b64 = BIO_new(BIO_f_base64());
            BIO *bio_mem = BIO_new(BIO_s_mem());
            BIO_push(bio_b64, bio_mem);
            BIO_write(bio_b64, md_value, md_len);
            BIO_flush(bio_b64);
            md_len = BIO_read(bio_mem, md_value, sizeof(md_value));
            md_value[md_len] = '\0';
            md_value[md_len - 1] = '\0'; // eat CR

            EVP_cleanup();

            if (strcmp((const char *)password, (const char *)md_value)) {
                if (conn_send(connection, "Invalid username/password.\n") < 0) return NULL;
                continue;
            }

            sqlite3_finalize(stmt);

            if (conn_send(connection, "Connected, obj_id=%d.\n", obj_id) < 0) return NULL;
            connection->obj_id = obj_id;
            mark_connected(connection, true);
        }
    }

    cmdloop(connection);
    mark_connected(connection, false);

    SSL_shutdown(connection->ssl);
    SSL_free(connection->ssl);
    close(connection->clientsocket);
    free(connection);
    return NULL;
}

int main(int argc, char **argv) { DBG();
    int rc = 0;
    int srv_sock = 0;
    SSL_CTX *srv_ctx = NULL;
    sqlite3 *db = NULL;

    rc = sqlite3_open("luamud.sqlite", &(db));
    if (rc) {
        sql_err("Can't open database '%s': %s\n", "luamud.sqlite", sqlite3_errmsg(db));
        return rc;
    }

    signal(SIGPIPE, SIG_IGN);
    srv_ctx = create_context();
    configure_context(srv_ctx);
    srv_sock = create_socket(1234);

    while(server_state == SERVER_RUNNING) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl = NULL;

        int client = accept(srv_sock, (struct sockaddr *)&addr, &len);

        if (client < 0) {
            perror("Unable to accept.");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(srv_ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            pthread_t t;
            pthread_attr_t ta;
            connection_t *conn_ptr = NULL;

            conn_ptr = calloc(sizeof(*conn_ptr), 1);
            conn_ptr->ssl = ssl;
            conn_ptr->clientsocket = client;
            conn_ptr->db = db;

            pthread_attr_init(&ta);
            pthread_attr_setdetachstate(&ta, PTHREAD_CREATE_DETACHED);
            pthread_create(&t, &ta, connected, conn_ptr);
        }
    }

    close(srv_sock);
    SSL_CTX_free(srv_ctx);
    sqlite3_close(db);
}
