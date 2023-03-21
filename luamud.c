#define i_implement // define this to implement many STC functions as shared symbols
#include <stc/cstr.h>

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

#define DEBUG

#define MUD_MARKER 0xBEADDEEF

char inbuf[1024];

typedef struct {
    sqlite3 *db;
} luamud_t;

typedef struct {
    int marker, id, par, loc, own;
} mud_obj_t;

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
#define DBG() { printf("%s\n", __func__); dumpstack(lua_state, "  "); }
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

int mud_prop_fnwriter(lua_State *lua_state, const void *p, size_t sz, void *ud) {
    mud_prop_fnbuf_t *b = ud;
    printf("b->pos = %lu, b->sz = %lu, sz = %lu\n", b->pos, b->sz, sz);
    while(sz + b->pos >= b->sz) {
        size_t newsz = b->sz * 2; // double each time
        printf("realloc %lu\n", newsz);
        b->buf = realloc(b->buf, newsz);
        if (!b->buf) {
            printf("OUT OF MEMORY!\n");
            return 1; // fail out
        }
        b->sz = newsz;
    }
    memcpy(b->buf + b->pos, p, sz);
    b->pos += sz;
    return 0;
}

const char *mud_prop_fnreader(lua_State *lua_state, void *data, size_t *sz) {
    mud_prop_fnbuf_t *b = data;
    *sz = b->sz;
    return (const char *)b->buf;
}

int mud_obj_set(lua_State *lua_state) {
    DBG();

    luamud_t *m = *((luamud_t **)lua_getextraspace(lua_state));
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

    if (proptype == LUA_TNIL) {
        if(sqlite3_prepare_v3(m->db, "delete from mud_prop where obj_id = ? and name = ?", -1, 0, &stmt, NULL) != SQLITE_OK) return mud_err(lua_state, "Unable to prepare query.");

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

        lua_pop(lua_state, 3);

        return 1;
    }

    // TODO: handle if the prop already exists

    if(sqlite3_prepare_v3(m->db, "insert into mud_prop(obj_id, name, type, val) values (?, ?, ?, ?)", -1, 0, &stmt, NULL) != SQLITE_OK)
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
            if(sqlite3_bind_int(stmt, 4, propval) != SQLITE_OK) {
                sqlite3_finalize(stmt);
                return sql_err("Unable to bind value.");
            }
            break;
        }
        case LUA_TSTRING: {
            const char *propval = lua_tostring(lua_state, -1);
            if(sqlite3_bind_text(stmt, 4, propval, -1, NULL) != SQLITE_OK) {
                sqlite3_finalize(stmt);
                return sql_err("Unable to bind value.");
            }
            break;
        }
        case LUA_TFUNCTION: {
            mud_prop_fnbuf_t b = {
                .buf = malloc(1024), .pos = 0, .sz = 1024
            };

            lua_dump(lua_state, mud_prop_fnwriter, &b, 0);
            if(sqlite3_bind_blob(stmt, 4, b.buf, b.pos, NULL) != SQLITE_OK) {
                free(b.buf);
                sqlite3_finalize(stmt);
                return sql_err("Unable to bind value.");
            }
            free(b.buf);
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

    return 1;
}

int mud_obj_get(lua_State *lua_state) {
    DBG();

    luamud_t *m = *((luamud_t **)lua_getextraspace(lua_state));
    mud_obj_t *obj = NULL;
    const char *propname = NULL;
    sqlite3_stmt *stmt = NULL;
    int sqlite3_rc = 0;

    if(lua_gettop(lua_state) < 2 || !lua_isstring(lua_state, -1))
        return mud_err(lua_state, "Invalid call.");
    propname = lua_tostring(lua_state, -1); lua_pop(lua_state, 1);
    obj = lua_touserdata(lua_state, -1); lua_pop(lua_state, 1);

    if (propname && *propname == '.') {
        if (!strncmp(propname, ".owner", 6)) {
        }
    }

    if (obj->marker != MUD_MARKER) return mud_err(lua_state, "Invalid object.");

    if(sqlite3_prepare_v3(m->db, "select type, val from mud_prop where obj_id = ? and name = ?", -1, 0, &stmt, NULL) != SQLITE_OK)
        return mud_err(lua_state, "Unable to prepare query.");

    if(sqlite3_bind_int(stmt, 1, obj->id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to bind ID.");
    }

    if(sqlite3_bind_text(stmt, 2, propname, -1, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to bind name.");
    }

    if(sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to fetch row.");
    } else {
        int proptype = sqlite3_column_int(stmt, 0);
        switch(proptype) {
            case LUA_TNUMBER: {
                lua_pushnumber(lua_state, sqlite3_column_int(stmt, 1));
                break;
            }
            case LUA_TSTRING: {
                lua_pushstring(lua_state, (const char *)sqlite3_column_text(stmt, 1));
                break;
            }
            case LUA_TFUNCTION: {
                mud_prop_fnbuf_t b = {
                    .buf = (uint8_t *)sqlite3_column_blob(stmt, 1),
                    .pos = 0,
                    .sz = sqlite3_column_bytes(stmt, 1)
                };
                lua_load(lua_state, mud_prop_fnreader, &b, "mudfn", "bt");
                break;
            }
            default:
                sqlite3_finalize(stmt);
                return mud_err(lua_state, "Invalid type of property.");
        }
    }

    sqlite3_finalize(stmt);

    return 1;
}

int push_mud_obj(lua_State *lua_state, int id, int par_id, int loc_id) {
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

int create_mud_obj(lua_State *lua_state, luamud_t *m) {
    sqlite3_stmt *stmt = NULL;
    int id = 0;

    if(sqlite3_prepare_v3(m->db, "insert into mud_obj(par_id, loc_id, own_id) values(0, 0, 0)", -1, 0, &stmt, NULL) != SQLITE_OK)
        return mud_err(lua_state, "Unable to prepare insert.");

    if(sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to create obj.");
    }
    sqlite3_finalize(stmt);

    if(sqlite3_prepare_v3(m->db, "select last_insert_rowid()", -1, 0, &stmt, NULL) != SQLITE_OK)
        return mud_err(lua_state, "Unable to prepare query.");

    if(sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to step select.");
    }

    id = sqlite3_column_int(stmt, 1);

    sqlite3_finalize(stmt);

    return push_mud_obj(lua_state, id, 0, 0);
}

int load_mud_obj(lua_State *lua_state, luamud_t *m, int obj_id) {
    sqlite3_stmt *stmt = NULL;

    if(sqlite3_prepare_v3(m->db, "select id, par_id, loc_id from mud_obj where id = ?", -1, 0, &stmt, NULL) != SQLITE_OK)
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
        sqlite3_column_int(stmt, 1),
        sqlite3_column_int(stmt, 2),
        sqlite3_column_int(stmt, 3)
    );

    sqlite3_finalize(stmt);

    return 1;
}

int mud_obj(lua_State *lua_state) {
    DBG();

    luamud_t *m = *((luamud_t **)lua_getextraspace(lua_state));
    sqlite3_stmt *stmt = NULL;
    int sqlite3_rc = 0;
    int r = 0;
    int obj_id = 0;
    mud_obj_t *mud_obj = NULL;

    if (lua_gettop(lua_state) < 1)
        return create_mud_obj(lua_state, m);

    if (!lua_isnumber(lua_state, 1))
        return mud_err(lua_state, "Need object ID");

    obj_id = lua_tointeger(lua_state, 1);
    lua_pop(lua_state, 1);

    return load_mud_obj(lua_state, m, obj_id);
}

int main_cont(lua_State *lua_state, int status, lua_KContext ctx) {
    luamud_t *m = (luamud_t *)ctx;
    sqlite3_close(m->db);
    return 0;
}

int create_socket(int port) {
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

SSL_CTX *create_context() {
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

void configure_context(SSL_CTX *ctx) {
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

typedef struct {
    SSL *ssl;
    int clientsocket, obj_id;
    luamud_t *mud;
} connection_t;

bool iscommand(char *buf, size_t buf_len, char *cmd) {
    size_t cmd_len = strlen(cmd);
    if (buf_len < cmd_len) return false;
    return strncmp(buf, cmd, cmd_len) == 0;
}

int conn_send(connection_t *connection, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    size_t sz = vsnprintf(buf, sizeof(buf), fmt, ap);
    return SSL_write(connection->ssl, buf, sz);
}

void command_who(connection_t *connection) {
    sqlite3_stmt *stmt = NULL;

    if(sqlite3_prepare_v3(connection->mud->db, "select obj_id, username from mud_auth where connected = 1", -1, 0, &stmt, NULL) != SQLITE_OK) {
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

void *connected(void *arg) {
    connection_t *connection = (connection_t *)arg;
    sqlite3_stmt *stmt = NULL;
    size_t readbytes = 0;

    lua_State *lua_state = luaL_newstate();
    void **es = (void **)lua_getextraspace(lua_state);
    *es = connection->mud;
    luaL_openlibs(lua_state);
    lua_register(lua_state, "mud_obj", mud_obj);

//    luaL_loadstring(lua_state, "debug.debug()");
//    return main_cont(lua_state, lua_pcall(lua_state, 0, LUA_MULTRET, 0), (lua_KContext)&connection->mud);

    regex_t preg;
    regmatch_t matches[3];
    regcomp(&preg, "connect ([^ ]*) (.*)", REG_EXTENDED);
    while(!connection->obj_id) { /* unauthenticated */
        if (conn_send(connection, "Connect: ") < 0) return NULL;

        readbytes = SSL_read(connection->ssl, inbuf, 1024);
        if (readbytes <= 0) break;
        inbuf[readbytes - 1] = '\0'; /* remove EOL, or mark end of buf */
        if(regexec(&preg, inbuf, 3, matches, 0) == 0) {
            cstr username = cstr_from_n(inbuf + matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);

            if(sqlite3_prepare_v3(connection->mud->db, "select obj_id, password, password_salt from mud_auth where username = ?", -1, 0, &stmt, NULL) != SQLITE_OK) {
                sql_err("Error: unable to prepare query.\n");
                return NULL;
            }

            if (sqlite3_bind_text(stmt, 1, cstr_str(&username), cstr_size(&username), NULL) != SQLITE_OK) {
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

            if (strcmp(password, (const char *)md_value)) {
                if (conn_send(connection, "Invalid username/password.\n") < 0) return NULL;
                continue;
            }

            sqlite3_finalize(stmt);

            if (conn_send(connection, "Connected, obj_id=%d.\n", obj_id) < 0) return NULL;
            connection->obj_id = obj_id;
        }
    }
    printf("auth\n");

    while(1) {
        readbytes = SSL_read(connection->ssl, inbuf, 1024);
        if (readbytes <= 0) break;

        if(iscommand(inbuf, readbytes, "@who")) {
            command_who(connection);
        }
    }

    SSL_shutdown(connection->ssl);
    SSL_free(connection->ssl);
    close(connection->clientsocket);
    free(connection);
    return NULL;
}

int main(int argc, char **argv) {
    int rc = 0;
    int srv_sock = 0;
    SSL_CTX *srv_ctx = NULL;
    luamud_t m;

    rc = sqlite3_open("luamud.sqlite", &(m.db));
    if (rc) {
        sql_err("Can't open database '%s': %s\n", "luamud.sqlite", sqlite3_errmsg(m.db));
        return rc;
    }

    signal(SIGPIPE, SIG_IGN);
    srv_ctx = create_context();
    configure_context(srv_ctx);
    srv_sock = create_socket(1234);

    while(1) {
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

            conn_ptr = malloc(sizeof(*conn_ptr));
            conn_ptr->ssl = ssl; conn_ptr->clientsocket = client; conn_ptr->mud = &m;

            pthread_attr_init(&ta);
            pthread_attr_setdetachstate(&ta, PTHREAD_CREATE_DETACHED);
            pthread_create(&t, &ta, connected, conn_ptr);
        }
    }

    close(srv_sock);
    SSL_CTX_free(srv_ctx);
}
