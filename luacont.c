#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdio.h>
#include <unistd.h> /* sleep */
#include <stdlib.h> /* malloc/free */
#include <string.h> /* memset */

int lua_sleep(lua_State *L) {
    if (lua_isnumber(L, 1)) {
        int sleeptime = lua_tonumber(L, 1);
        lua_pop(L, 1);
        yield();
        sleep(sleeptime);
    } /* otherwise do nothing */

    return 1;
}

void luahook(lua_State *L, lua_Debug *ar) {
    printf("HOOK\n");
}

int main(int argc, char **argv) {
    lua_State *L = NULL, *L2 = NULL;
    int lua_result = 0;

    L = luaL_newstate();
    luaL_openlibs(L);
    lua_register(L, "sleep", lua_sleep);
    luaL_loadstring(L, "x = 1; while true do print(x); x = x + 1; sleep(2); end");
    lua_sethook(L, luahook, LUA_MASKCOUNT, 10);
    lua_pcall(L, 0, LUA_MULTRET, 0);

    L2 = luaL_newstate();
    luaL_openlibs(L2);
    lua_register(L2, "sleep", lua_sleep);
    luaL_loadstring(L2, "x = 100; while true do print(x); x = x + 1; sleep(2); end");
    lua_pcall(L2, 0, LUA_MULTRET, 0);
}
