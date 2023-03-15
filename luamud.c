#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdio.h>
#include <sqlite3.h>

typedef struct {
    sqlite3 *db;
} luamud_t;

int mud_obj_get(lua_State *lua_state) {
    return 1;
}

int mud_obj(lua_State *lua_state) {
    luamud_t *m = *((luamud_t **)lua_getextraspace(lua_state));
    sqlite3_stmt *stmt = NULL;
    int sqlite3_rc = 0;
    int r = 0;

    if (lua_gettop(lua_state) < 1 || !lua_isnumber(lua_state, 1)) {
        lua_pushliteral(lua_state, "Need object ID");
        lua_error(lua_state);
        return 1;
    }

    int obj_id = lua_tointeger(lua_state, 1);

    printf("OBJ ID: %d\n", obj_id);

    // TODO: create obj if doesn't exist?

    // TODO: handle error conditions
    if(sqlite3_prepare_v3(m->db, "select id from mud_obj where id = ?", -1, 0, &stmt, NULL) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to prepare query.");
        lua_error(lua_state);
        return 1;
    }
    if(sqlite3_bind_int(stmt, 1, obj_id) != SQLITE_OK) {
        lua_pushliteral(lua_state, "Unable to bind ID.");
        lua_error(lua_state);
        return 1;
    }
    if(sqlite3_step(stmt) != SQLITE_ROW) {
        lua_pushliteral(lua_state, "Unable to fetch row.");
        lua_error(lua_state);
        return 1;
    }

    printf("finalizing\n");
    sqlite3_finalize(stmt);

    lua_pushinteger(lua_state, 5);

/*    lua_newtable(lua_state);
    lua_pushliteral(lua_state, "__get");
    lua_pushcclosure(lua_state, mud_obj_get, 1);
    lua_setmetatable(lua_state, -1);
    */

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
    lua_getglobal(lua_state, "mud_obj");
    lua_pushinteger(lua_state, 0);
    lua_call(lua_state, 1, 1);
    lua_result = lua_tointeger(lua_state, 1);
    printf("result: %d\n", lua_result);
    lua_pop(lua_state, -1);

    sqlite3_close(m.db);

    return 0;
}
