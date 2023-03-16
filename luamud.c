#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h> /* malloc/free */
#include <string.h> /* memset */

#define MUD_MARKER 0xBEADDEEF

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
      case LUA_TNUMBER:
        printf("%g\n",lua_tonumber(L,i));
        break;
      case LUA_TSTRING:
        printf("%s\n",lua_tostring(L,i));
        break;
      case LUA_TBOOLEAN:
        printf("%s\n", (lua_toboolean(L, i) ? "true" : "false"));
        break;
      case LUA_TNIL:
        printf("%s\n", "nil");
        break;
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
            return mud_err(lua_state, "Unable to bind obj id.");
        }

        if(sqlite3_bind_int(stmt, 1, obj->id) != SQLITE_OK) {
            sqlite3_finalize(stmt);
            return mud_err(lua_state, "Unable to bind obj id.");
        }

        if(sqlite3_bind_text(stmt, 2, propname, -1, NULL) != SQLITE_OK) {
            sqlite3_finalize(stmt);
            return mud_err(lua_state, "Unable to bind name.");
        }

        if(sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return mud_err(lua_state, "Unable to bind name.");
        }

        sqlite3_finalize(stmt);

        lua_pop(lua_state, 3);

        return 1;
    }

    // TODO: handle if the prop already exists

    if(sqlite3_prepare_v3(m->db, "insert into mud_prop(obj_id, name, type, val) values (?, ?, ?, ?)", -1, 0, &stmt, NULL) != SQLITE_OK) return mud_err(lua_state, "Unable to prepare query.");

    if(sqlite3_bind_int(stmt, 1, obj->id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to bind ID.");
    }

    if(sqlite3_bind_text(stmt, 2, propname, -1, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to bind name.");
    }

    if(sqlite3_bind_int(stmt, 3, proptype) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to bind ID.");
    }

    switch (proptype) {
        case LUA_TBOOLEAN:
        case LUA_TNUMBER: {
            int propval = lua_tonumber(lua_state, -1);
            if(sqlite3_bind_int(stmt, 4, propval) != SQLITE_OK) {
                sqlite3_finalize(stmt);
                return mud_err(lua_state, "Unable to bind value.");
            }
            break;
        }
        case LUA_TSTRING: {
            const char *propval = lua_tostring(lua_state, -1);
            if(sqlite3_bind_text(stmt, 4, propval, -1, NULL) != SQLITE_OK) {
                sqlite3_finalize(stmt);
                return mud_err(lua_state, "Unable to bind value.");
            }
            break;
        }
        default:
            sqlite3_finalize(stmt);
            return mud_err(lua_state, "Invalid type.");
    }

    lua_pop(lua_state, 3);

    if(sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Odd return from step.");
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
            case LUA_TNUMBER:
                lua_pushnumber(lua_state, sqlite3_column_int(stmt, 1));
                break;
            case LUA_TSTRING:
                lua_pushstring(lua_state, (const char *)sqlite3_column_text(stmt, 1));
                break;
            default:
                sqlite3_finalize(stmt);
                return mud_err(lua_state, "Invalid type of property.");
        }
    }

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

    if (lua_gettop(lua_state) < 1 || !lua_isnumber(lua_state, 1))
        return mud_err(lua_state, "Need object ID");

    obj_id = lua_tointeger(lua_state, 1);
    lua_pop(lua_state, 1);

    // TODO: create obj if doesn't exist?

    if(sqlite3_prepare_v3(m->db, "select id, par_id, loc_id from mud_obj where id = ?", -1, 0, &stmt, NULL) != SQLITE_OK)
        return mud_err(lua_state, "Unable to prepare query.");

    if(sqlite3_bind_int(stmt, 1, obj_id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to bind ID.");
    }

    if(sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return mud_err(lua_state, "Unable to fetch row.");
    }

    mud_obj = malloc(sizeof(*mud_obj));
    memset(mud_obj, 0, sizeof(*mud_obj));
    mud_obj->marker = MUD_MARKER;
    mud_obj->id = sqlite3_column_int(stmt, 1);
    mud_obj->par = sqlite3_column_int(stmt, 2);
    mud_obj->loc = sqlite3_column_int(stmt, 3);

    sqlite3_finalize(stmt);

    lua_pushlightuserdata(lua_state, mud_obj);
//    lua_newtable(lua_state);
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

int main(int argc, char **argv) {
    int rc = 0;
    luamud_t m;
    sqlite3_stmt *stmt = NULL;
    lua_State *lua_state = NULL;
    int lua_result = 0;

    rc = sqlite3_open("luamud.sqlite", &(m.db));
    if (rc) {
        fprintf(stderr, "Can't open database '%s': %s\n", "luamud.sqlite", sqlite3_errmsg(m.db));
        return rc;
    }

    lua_state = luaL_newstate();
    void **es = (void **)lua_getextraspace(lua_state);
    *es = &m;
    luaL_openlibs(lua_state);
    lua_register(lua_state, "mud_obj", mud_obj);
    luaL_loadstring(lua_state, "m = mud_obj(0); print(m.name); m.foo = 12; m.foo = nil");
    lua_pcall(lua_state, 0, LUA_MULTRET, 0);

    sqlite3_close(m.db);

    return 0;
}
