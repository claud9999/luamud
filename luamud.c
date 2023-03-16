#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h> /* malloc/free */
#include <string.h> /* memset */

typedef struct {
    sqlite3 *db;
} luamud_t;

typedef struct {
    int id, par, loc;
} mud_obj_t;

static void dumpstack (lua_State *L) {
  int top=lua_gettop(L);
  for (int i=1; i <= top; i++) {
    printf("%d\t%s\t", i, luaL_typename(L,i));
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
            printf("%s - %s\n",
                lua_typename(L, lua_type(L, -2)),
                lua_typename(L, lua_type(L, -1))
                );
            lua_pop(L, 1);
        }
      default:
        printf("%p\n",lua_topointer(L,i));
        break;
    }
  }
}

int mud_obj_set(lua_State *lua_state) {
    luamud_t *m = *((luamud_t **)lua_getextraspace(lua_state));
    mud_obj_t *obj = NULL;
    const char *propname = NULL;
    const char *propval = NULL;
    sqlite3_stmt *stmt = NULL;
    int sqlite3_rc = 0;

    if(lua_gettop(lua_state) < 3 || !lua_isstring(lua_state, -2)) {
        lua_pushliteral(lua_state, "Invalid call.");
        lua_error(lua_state);
        return 1;
    }
    propval = lua_tostring(lua_state, -1); lua_pop(lua_state, 1);
    propname = lua_tostring(lua_state, -1); lua_pop(lua_state, 1);
    obj = lua_touserdata(lua_state, -1); lua_pop(lua_state, 1);

    if(sqlite3_prepare_v3(m->db, "insert into mud_prop(obj_id, name, val) values (?, ?, ?)", -1, 0, &stmt, NULL) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to prepare query.");
        lua_error(lua_state);
        return 1;
    }

    if(sqlite3_bind_int(stmt, 1, obj->id) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to bind ID.");
        lua_error(lua_state);
        goto mud_obj_set_end;
    }

    if(sqlite3_bind_text(stmt, 2, propname, -1, NULL) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to bind name.");
        lua_error(lua_state);
        goto mud_obj_set_end;
    }

    if(sqlite3_bind_text(stmt, 3, propval, -1, NULL) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to bind value.");
        lua_error(lua_state);
        goto mud_obj_set_end;
    }

    if(sqlite3_step(stmt) != SQLITE_DONE) {
        lua_pushliteral(lua_state, "Odd return from step.");
        lua_error(lua_state);
        goto mud_obj_set_end;
    }

mud_obj_set_end:
    sqlite3_finalize(stmt);

    return 1;
}

int mud_obj_get(lua_State *lua_state) {
    luamud_t *m = *((luamud_t **)lua_getextraspace(lua_state));
    mud_obj_t *obj = NULL;
    const char *propname = NULL;
    sqlite3_stmt *stmt = NULL;
    int sqlite3_rc = 0;

    if(lua_gettop(lua_state) < 2 || !lua_isstring(lua_state, -1)) {
        lua_pushliteral(lua_state, "Invalid call.");
        lua_error(lua_state);
        return 1;
    }
    propname = lua_tostring(lua_state, -1); lua_pop(lua_state, 1);
    obj = lua_touserdata(lua_state, -1); lua_pop(lua_state, 1);

    if(sqlite3_prepare_v3(m->db, "select val from mud_prop where obj_id = ? and name = ?", -1, 0, &stmt, NULL) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to prepare query.");
        lua_error(lua_state);
        return 1;
    }

    if(sqlite3_bind_int(stmt, 1, obj->id) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to bind ID.");
        lua_error(lua_state);
        goto mud_obj_get_end;
    }

    if(sqlite3_bind_text(stmt, 2, propname, -1, NULL) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to bind name.");
        lua_error(lua_state);
        goto mud_obj_get_end;
    }

    if(sqlite3_step(stmt) != SQLITE_ROW) {
        lua_pushliteral(lua_state, "Unable to fetch row.");
        lua_error(lua_state);
        goto mud_obj_get_end;
    } else {
        lua_pushstring(lua_state, (const char *)sqlite3_column_text(stmt, 0));
    }

mud_obj_get_end:
    sqlite3_finalize(stmt);

    return 1;
}

int mud_obj(lua_State *lua_state) {
    luamud_t *m = *((luamud_t **)lua_getextraspace(lua_state));
    sqlite3_stmt *stmt = NULL;
    int sqlite3_rc = 0;
    int r = 0;
    int obj_id = 0;
    mud_obj_t *mud_obj = NULL;

    if (lua_gettop(lua_state) < 1 || !lua_isnumber(lua_state, 1)) {
        lua_pushliteral(lua_state, "Need object ID");
        lua_error(lua_state);
        return 1;
    }

    obj_id = lua_tointeger(lua_state, 1);
    lua_pop(lua_state, 1);

    // TODO: create obj if doesn't exist?

    if(sqlite3_prepare_v3(m->db, "select id, par_id, loc_id from mud_obj where id = ?", -1, 0, &stmt, NULL) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to prepare query.");
        lua_error(lua_state);
        return 1;
    }

    if(sqlite3_bind_int(stmt, 1, obj_id) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to bind ID.");
        lua_error(lua_state);
        goto mud_obj_end;
    }

    if(sqlite3_step(stmt) != SQLITE_ROW) {
        lua_pushliteral(lua_state, "Unable to fetch row.");
        lua_error(lua_state);
        goto mud_obj_end;
    } else {
        mud_obj = malloc(sizeof(*mud_obj));
        memset(mud_obj, 0, sizeof(*mud_obj));
        mud_obj->id = sqlite3_column_int(stmt, 1);
        mud_obj->par = sqlite3_column_int(stmt, 2);
        mud_obj->loc = sqlite3_column_int(stmt, 3);
    }

    lua_pushlightuserdata(lua_state, mud_obj);
    lua_createtable(lua_state, 0, 1); /* narr, nrec */

    lua_pushliteral(lua_state, "__index");
    lua_pushcfunction(lua_state, mud_obj_get);
    lua_rawset(lua_state, -3);

    lua_pushliteral(lua_state, "__newindex");
    lua_pushcfunction(lua_state, mud_obj_set);
    lua_rawset(lua_state, -3);

    lua_setmetatable(lua_state, -2);

mud_obj_end:
    sqlite3_finalize(stmt);

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
    luaL_loadstring(lua_state, "m = mud_obj(0); print(m.name); m.foo = 'bar'");
    lua_pcall(lua_state, 0, LUA_MULTRET, 0);

    sqlite3_close(m.db);

    return 0;
}
