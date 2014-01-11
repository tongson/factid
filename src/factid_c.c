#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <limits.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "strlcpy.h"

struct sysinfo info;

static int Fsysinfo(lua_State *L)
{
	if (sysinfo(&info)) {
		lua_pushnil(L);
		lua_pushfstring(L, "Failed to get sysinfo, (%s)", strerror(errno));
		return 2;
	}
	return 0;
}

static int pusherrno(lua_State *L, const char *error)
{
        lua_pushnil(L);
        lua_pushfstring(L, LUA_QS" : "LUA_QS, error, strerror(errno));
        lua_pushinteger(L, errno);
        return 3;
}

static int Fuptime(lua_State *L)
{
	struct sysinfo info = {0};
	if (sysinfo(&info) != 0)
		return pusherrno(L, "sysinfo(2) error");
	lua_pushinteger(L, info.uptime);
	return 1;
}

static int Floads(lua_State *L)
{
	int l;
	struct sysinfo info = {0};
	if (sysinfo(&info) != 0)
		return pusherrno(L, "sysinfo(2) error");
	lua_createtable(L, 3, 3);
	for (l=0; l<3; l++) {
		lua_pushnumber(L, info.loads[l]/65536.00);
		lua_rawseti(L, -2, l+1);
	}
	return 1;
}

static int Fmem(lua_State *L)
{
	struct sysinfo info = {0};
	if (sysinfo(&info) != 0)
		return pusherrno(L, "sysinfo(2) error");

	lua_createtable(L, 0, 9);

	lua_pushinteger(L, info.mem_unit);
	lua_setfield(L, -2, "mem_unit");

	lua_pushnumber(L, info.freehigh);
	lua_setfield(L, -2, "freehigh");

	lua_pushnumber(L, info.totalhigh);
	lua_setfield(L, -2, "totalhigh");

	lua_pushnumber(L, info.freeswap);
	lua_setfield(L, -2, "freeswap");

	lua_pushnumber(L, info.totalswap);
	lua_setfield(L, -2, "totalswap");

	lua_pushnumber(L, info.bufferram);
	lua_setfield(L, -2, "bufferram");

	lua_pushnumber(L, info.sharedram);
	lua_setfield(L, -2, "sharedram");

	lua_pushnumber(L, info.freeram);
	lua_setfield(L, -2, "freeram");

	lua_pushnumber(L, info.totalram);
	lua_setfield(L, -2, "totalram");
	return 1;
}

static int Fprocs(lua_State *L)
{
	struct sysinfo info = {0};
	if (sysinfo(&info) != 0)
		return pusherrno(L, "sysinfo(2) error");
	lua_pushinteger(L, info.procs);
	return 1;
}

static int Fsysconf(lua_State *L)
{
	long openmax = sysconf(_SC_OPEN_MAX);
	long procs = sysconf(_SC_NPROCESSORS_CONF);
	long procsonline = sysconf(_SC_NPROCESSORS_ONLN);
	long pagesize = sysconf(_SC_PAGESIZE);
	long physpages = sysconf(_SC_PHYS_PAGES);
	long avphyspages = sysconf(_SC_AVPHYS_PAGES);

	lua_createtable(L, 0, 6);

	lua_pushnumber(L, openmax);
	lua_setfield(L, -2, "openmax");

	lua_pushnumber(L, procs);
	lua_setfield(L, -2, "procs");

	lua_pushnumber(L, procsonline);
	lua_setfield(L, -2, "procsonline");

	lua_pushnumber(L, pagesize);
	lua_setfield(L, -2, "pagesize");

	lua_pushnumber(L, physpages);
	lua_setfield(L, -2, "physpages");

	lua_pushnumber(L, avphyspages);
	lua_setfield(L, -2, "avphyspages");

	return 1;
}

static int Fhostname(lua_State *L)
{
	char *hostname;
	void *ud;
	lua_Alloc lalloc = lua_getallocf(L, &ud);
	long max = sysconf(_SC_HOST_NAME_MAX);
	if (max == -1 && errno == EINVAL)
		max = _POSIX_HOST_NAME_MAX;
	hostname = lalloc(ud, NULL, 0, (size_t)max+1);
	if (!hostname)
		return pusherror(L, "Memory allocation error");
	if (gethostname(hostname, (size_t)max) == 0) {
		lua_pushstring(L, hostname);
	} else {
		lalloc(ud, hostname, (size_t)max+1, 0);
		return pusherrno(L, "gethostname(2) error");
	}
	lalloc(ud, hostname, (size_t)max+1, 0);
	return 1;
}

static int Funame(lua_State *L)
{
	struct utsname uts = {0};
	char buf[_UTSNAME_LENGTH];
	char dbuf[_UTSNAME_DOMAIN_LENGTH];

	if (uname(&uts) == -1)
		return pusherrno(L, "uname(2) error");

        lua_createtable(L, 0, 5);

	memset(&buf, 0, _UTSNAME_LENGTH);
	strncpy(buf, uts.sysname, _UTSNAME_LENGTH);
	buf[_UTSNAME_LENGTH-1] = '\0';
	lua_pushstring(L, buf);
        lua_setfield(L, -2, "sysname");
	lua_pushstring(L, nodename);
	lua_setfield(L, -2, "nodename");
	lua_pushstring(L, release);
	lua_setfield(L, -2, "release");
	lua_pushstring(L, version);
	lua_setfield(L, -2, "version");
	lua_pushstring(L, machine);
	lua_setfield(L, -2, "machine");

	return 1;
}

static const luaL_Reg syslib[] =
{
	{"uptime", Fuptime},
	{"loads", Floads},
	{"mem", Fmem},
	{"procs", Fprocs},
	{"sysconf", Fsysconf},
	{"hostname", Fhostname},
	{"uname", Funame},
	{"hostid", Fhostid},
	{"timezone", Ftimezone},
	{"mount", Fmount},
	{NULL, NULL}
};

LUALIB_API int luaopen_factid_c(lua_State *L)
{
	luaL_newlib(L, syslib);
	return 1;
}

