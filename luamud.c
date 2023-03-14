#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdio.h>
#include <sqlite3.h>

int api_foobar(lua_State *lua_state) {
    lua_pushinteger(lua_state, 5);
    return 1;
}

void lua_err(lua_State *lua_state) {
    const char *message = lua_tostring(lua_state, -1);
    puts(message);
    lua_pop(lua_state, 1);
}

int main(int argc, char **argv) {
    int rc = 0;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    lua_State *lua_state = NULL;
    int lua_result = 0;

    rc = sqlite3_open("luamud.sqlite", &db);
    if (rc) {
        fprintf(stderr, "Can't open database '%s': %s\n", "luamud.sqlite", sqlite3_errmsg(db));
        return rc;
    }

    lua_state = luaL_newstate();
    luaL_openlibs(lua_state);
    lua_register(lua_state, "foobar", api_foobar);
    if (luaL_loadstring(lua_state, "return foobar()") != LUA_OK) {
        lua_err(lua_state);
    } else {
        if(lua_pcall(lua_state, 0, LUA_MULTRET, 0) != LUA_OK) {
            lua_err(lua_state);
        } else {
            if(!lua_isnumber(lua_state, -1)) lua_err(lua_state);
            else {
                lua_result = lua_tonumber(lua_state, -1);
                lua_pop(lua_state, 1);
                printf("result = %d\n", lua_result);
            }
        }
    }

    rc = sqlite3_prepare_v3(db, "select id, val from mud_obj, mud_prop where mud_obj.id = mud_prop.obj_id and mud_prop.name = 'name'", -1, 0, &stmt, NULL);
    while((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        sqlite3_int64 id = sqlite3_column_int64(stmt, 0);
        printf("FOO: %lld\n", id);
    }

    sqlite3_close(db);

    return 0;
}
