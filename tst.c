#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <unistd.h> /* sleep */
#include <stdlib.h> /* malloc/free */
#include <string.h> /* memset */
#include <pthread.h>

int luasleep(lua_State *L) {
    if(lua_gettop(L) < 1 || !lua_isnumber(L, -1)) {
        lua_pushstring(L, "Err, invalid sleep parameter.");
        lua_error(L);
        return 1;
    }
    sleep(lua_tonumber(L, -1));
    lua_pop(L, 1);
    return 1;
}

void *fn1() {
    printf("FN1\n");
    lua_State *L = NULL;

    L = luaL_newstate();
    luaL_openlibs(L);
    lua_register(L, "sleep", luasleep);
    luaL_loadstring(L, "m = 0; while (m < 1000) do print(m); m = m + 1; sleep(1); end; print(m)");
    lua_pcall(L, 0, LUA_MULTRET, 0);
    return NULL;
}

void *fn2() {
    printf("FN2\n");
    lua_State *L = NULL;

    L = luaL_newstate();
    luaL_openlibs(L);
    lua_register(L, "sleep", luasleep);
    luaL_loadstring(L, "m = 1000; while (m < 2000) do print(m); m = m + 1; sleep(1); end; print(m)");
    lua_pcall(L, 0, LUA_MULTRET, 0);
    return NULL;
}

int main(int argc, char **argv) {
    pthread_t t1;
    pthread_attr_t ta1;

    pthread_attr_init(&ta1);
    pthread_attr_setdetachstate(&ta1, PTHREAD_CREATE_DETACHED);
    pthread_create(&t1, &ta1, fn1, NULL);

    pthread_t t2;
    pthread_attr_t ta2;

    pthread_attr_init(&ta2);
    pthread_attr_setdetachstate(&ta2, PTHREAD_CREATE_JOINABLE);
    pthread_create(&t2, NULL, fn2, NULL);
    pthread_join(t2, NULL);
}
