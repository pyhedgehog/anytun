/*
 *  anytun
 *
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methodes used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2009 Othmar Gsenger, Erwin Nindl, 
 *                          Christian Pointner <satp@wirdorange.org>
 *
 *  This file is part of Anytun.
 *
 *  Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  any later version.
 *
 *  Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with anytun.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ANYTUN_initLua_hpp_INCLUDED
#define ANYTUN_initLua_hpp_INCLUDED
#ifndef NO_LUA
#include "../datatypes.h"
#include "../log.h"

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

#include "anytun_lua_bytecode.h"

#define LUA_MAIN_FUNC "test"

static const luaL_Reg anytun_lualibs[] = {
  {"", luaopen_base},
  {LUA_LOADLIBNAME, luaopen_package},
  {LUA_TABLIBNAME, luaopen_table},
  {LUA_STRLIBNAME, luaopen_string},
  {LUA_MATHLIBNAME, luaopen_math},
//  {LUA_LOGLIBNAME, luaopen_log},
  {NULL, NULL}
};

void initLua(lua_State* L)
{
  const luaL_Reg *lib = anytun_lualibs;
  for (; lib->func; lib++) {
    lua_pushcfunction(L, lib->func);
    lua_pushstring(L, lib->name);
    lua_call(L, 1, 0);
  }

  int ret = luaL_loadbuffer(L, anytun_lua_bytecode, sizeof(anytun_lua_bytecode), "anytun-lua");
  if(ret) {
    std::string err_str = luaL_checkstring(L, -1);
    switch(ret) {
    case LUA_ERRSYNTAX: AnytunError::throwErr() << "luaL_loadbuffer() syntax error: " << err_str;
    case LUA_ERRMEM: AnytunError::throwErr() << "luaL_loadbuffer() malloc error: " << err_str;
    default: AnytunError::throwErr() << "luaL_loadbuffer() unknown error: " << err_str;
    }
  }

  ret = lua_pcall(L, 0, 0, 0);
  if(ret) {
    std::string err_str = luaL_checkstring(L, -1);
    switch(ret) {
    case LUA_ERRRUN: AnytunError::throwErr() << "lua_pcall() runtime error: " << err_str;
    case LUA_ERRMEM: AnytunError::throwErr() << "lua_pcall() malloc error: " << err_str;
    case LUA_ERRERR: AnytunError::throwErr() << "lua_pcall() error at error handler function: " << err_str;
    }
  }
}

void runLua(lua_State* L)
{
  lua_getglobal(L, LUA_MAIN_FUNC);
  if(!lua_isfunction(L, -1))
    AnytunError::throwErr() << "there is no function '" << LUA_MAIN_FUNC << "' inside anytun lua bytecode";

  int ret = lua_pcall(L, 0, LUA_MULTRET, 0);
  if(ret) {
    std::string err_str = luaL_checkstring(L, -1);
    switch(ret) {
    case LUA_ERRRUN: AnytunError::throwErr() << "lua_pcall(" << LUA_MAIN_FUNC << ") runtime error: " << err_str;
    case LUA_ERRMEM: AnytunError::throwErr() << "lua_pcall(" << LUA_MAIN_FUNC << ") malloc error: " << err_str;
    case LUA_ERRERR: AnytunError::throwErr() << "lua_pcall(" << LUA_MAIN_FUNC << ") error at error handler function: " << err_str;
    }
  }

  int n = lua_gettop(L);
  cLog.msg(Log::PRIO_DEBUG) << "Lua: " << LUA_MAIN_FUNC << " returned " << n << " values";
  for (int i = 1; i <= n; i++)
    cLog.msg(Log::PRIO_DEBUG) << "return value [" << i << "] = '" << luaL_checkstring(L, i) << "'";
}

void luaThread()
{
  lua_State *L;
  L = luaL_newstate();
  if(!L) {
    cLog.msg(Log::PRIO_ERROR) << "can't create lua state, Lua thread stops now";
    return;
  }

  bool err = false;
  try
  {
    initLua(L);
    cLog.msg(Log::PRIO_DEBUG) << "Lua initialization finished";
    runLua(L);
  }
  catch(std::runtime_error& e) {
    cLog.msg(Log::PRIO_ERROR) << "Lua thread died due to an uncaught runtime_error: " << e.what();
    err = true;
  }
  catch(std::exception& e) {
    cLog.msg(Log::PRIO_ERROR) << "Lua thread died due to an uncaught exception: " << e.what();
    err = true;
  }
 
  if(!err)
    cLog.msg(Log::PRIO_NOTICE) << "Lua thread stops now";

  lua_close(L);
}


#endif
#endif
