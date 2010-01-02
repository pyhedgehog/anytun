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

#include "../datatypes.h"
#include "../log.h"
#include "luaLog.h"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

static int l_log_add_target(lua_State *L)
{
  try
  {
    cLog.addTarget(luaL_checkstring(L,1));
  }
  catch(std::exception& e) {
    luaL_error(L, std::string("log.addTarget failed: ").append(e.what()).c_str());
  }
  return 0;
}

static int l_log_printf(lua_State *L)
{
  int numargs = lua_gettop(L);
  if(numargs < 2)
    return luaL_error(L, "log.printf too few arguments");

  if(numargs > 2) {
    lua_getglobal(L, "string");
    lua_pushliteral(L, "format");
    lua_gettable(L, -2);
    lua_insert(L, 2);
    lua_remove(L, -1);
    lua_call(L, numargs - 1, 1);
  }
  
  try
  {
    int prio = luaL_checkint(L,1);
    cLog.msg(prio) << luaL_checkstring(L, 2);
  }
  catch(std::exception& e) {
    luaL_error(L, std::string("log.add_target failed:").append(e.what()).c_str());
  }
  return 0;
}

static const struct luaL_reg log_funcs [] = {
  { "addTarget", l_log_add_target },
  { "printf", l_log_printf },
  { NULL, NULL }
};


LUALIB_API int luaopen_log(lua_State *L) 
{
  luaL_register(L, LUA_LOGLIBNAME, log_funcs);
  lua_pushliteral(L, "ERROR");
  lua_pushinteger(L, Log::PRIO_ERROR);
  lua_settable(L, -3);
  lua_pushliteral(L, "WARNING");
  lua_pushinteger(L, Log::PRIO_WARNING);
  lua_settable(L, -3);
  lua_pushliteral(L, "NOTICE");
  lua_pushinteger(L, Log::PRIO_NOTICE);
  lua_settable(L, -3);
  lua_pushliteral(L, "INFO");
  lua_pushinteger(L, Log::PRIO_INFO);
  lua_settable(L, -3);
  lua_pushliteral(L, "DEBUG");
  lua_pushinteger(L, Log::PRIO_DEBUG);
  lua_settable(L, -3);
  return 1;
}
