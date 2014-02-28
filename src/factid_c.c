#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <limits.h>
#include <time.h>
#include <locale.h>
#include <mntent.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "strlcpy.h"

static int pusherror(lua_State *L, char *error)
{
	lua_pushnil(L);
	lua_pushstring(L, error);
	return 2;
}

static int pusherrno(lua_State *L, char *error)
{
        lua_pushnil(L);
        lua_pushfstring(L, LUA_QS" : "LUA_QS, error, strerror(errno));
        lua_pushinteger(L, errno);
        return 3;
}

static int Fuptime(lua_State *L)
{
	struct sysinfo info = {0};
	if (sysinfo(&info) != 0) return pusherrno(L, "sysinfo(2) error");
	lua_pushinteger(L, info.uptime);
	return 1;
}

static int Floads(lua_State *L)
{
	int l;
	struct sysinfo info = {0};
	if (sysinfo(&info) == -1) return pusherrno(L, "sysinfo(2) error");
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
	if (sysinfo(&info) == -1) return pusherrno(L, "sysinfo(2) error");

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
	if (sysinfo(&info) == -1) return pusherrno(L, "sysinfo(2) error");
	lua_pushinteger(L, info.procs);
	return 1;
}

static int Fsysconf(lua_State *L)
{
	struct {
		char *name;
		long sc;
	} m[] = {
		{"openmax", sysconf(_SC_OPEN_MAX)},
		{"procs", sysconf(_SC_NPROCESSORS_CONF)},
		{"procsonline", sysconf(_SC_NPROCESSORS_ONLN)},
		{"pagesize", sysconf(_SC_PAGESIZE)},
		{"physpages", sysconf(_SC_PHYS_PAGES)},
		{"avphyspages", sysconf(_SC_AVPHYS_PAGES)}
	};

	lua_createtable(L, 0, 6);
	int c;
        for (c=0; c<sizeof(m)/sizeof(*m); c++) {
		lua_pushnumber(L, m[c].sc);
		lua_setfield(L, -2, m[c].name);
	}
	return 1;
}

static int Fhostname(lua_State *L)
{
	char *hostname;
	void *ud;
	lua_Alloc lalloc = lua_getallocf(L, &ud);
	long max = sysconf(_SC_HOST_NAME_MAX);
	if (max == -1 && errno == EINVAL) max = _POSIX_HOST_NAME_MAX;
	hostname = lalloc(ud, NULL, 0, (size_t)max+1);
	if (!hostname) return pusherror(L, "Memory allocation error");
	if (!gethostname(hostname, (size_t)max)) {
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

	memset(&buf, 0, _UTSNAME_LENGTH);
	strncpy(buf, uts.nodename, _UTSNAME_LENGTH);
	buf[_UTSNAME_LENGTH-1] = '\0';
	lua_pushstring(L, buf);
	lua_setfield(L, -2, "nodename");

	memset(&buf, 0, _UTSNAME_LENGTH);
	strncpy(buf, uts.release, _UTSNAME_LENGTH);
	buf[_UTSNAME_LENGTH-1] = '\0';
	lua_pushstring(L, buf);
	lua_setfield(L, -2, "release");

	memset(&buf, 0, _UTSNAME_LENGTH);
	strncpy(buf, uts.version, _UTSNAME_LENGTH);
	buf[_UTSNAME_LENGTH-1] = '\0';
	lua_pushstring(L, buf);
	lua_setfield(L, -2, "version");

	memset(&buf, 0, _UTSNAME_LENGTH);
	strncpy(buf, uts.machine, _UTSNAME_LENGTH);
	buf[_UTSNAME_LENGTH-1] = '\0';
	lua_pushstring(L, buf);
	lua_setfield(L, -2, "machine");

	memset(&dbuf, 0, _UTSNAME_DOMAIN_LENGTH);
#ifdef _GNU_SOURCE
	strncpy(dbuf, uts.domainname, _UTSNAME_DOMAIN_LENGTH);
#else
	strncpy(dbuf, uts.__domainname, _UTSNAME_DOMAIN_LENGTH);
#endif
	dbuf[_UTSNAME_DOMAIN_LENGTH-1] = '\0';
	lua_pushstring(L, dbuf);
	lua_setfield(L, -2, "domainname");

	return 1;
}

static int Fhostid(lua_State *L)
{
	char hostid[9];
	snprintf(hostid, sizeof(hostid), "%08lx", gethostid());
	lua_pushstring(L, hostid);
	return 1;
}

static int Ftimezone(lua_State *L)
{
	struct tm time = {0};
	char tzbuf[4];
	setlocale(LC_TIME, "C");
	if ((strftime(tzbuf, sizeof(tzbuf-1), "%Z", &time)) == 0)
		return pusherror(L, "strftime(3) error");
	lua_pushstring(L, tzbuf);
	return 1;
}

static int Fmount(lua_State *L)
{
	struct mntent *m = {0};
	FILE *mtab = setmntent("/etc/mtab", "r");
	if (!mtab) mtab = setmntent("/proc/self/mounts", "r");
	if (!mtab) return pusherrno(L, "setmntent(3) error");

	lua_newtable(L);
	int c;
	for (c = 0; (m = getmntent(mtab)) != NULL; c++) {
		lua_createtable(L, 0, 6);
		lua_pushfstring(L, "%s", m->mnt_fsname);
		lua_setfield(L, -2, "fsname");
		lua_pushfstring(L, "%s", m->mnt_dir);
		lua_setfield(L, -2, "dir");
		lua_pushfstring(L, "%s", m->mnt_type);
		lua_setfield(L, -2, "type");
		lua_pushfstring(L, "%s", m->mnt_opts);
		lua_setfield(L, -2, "opts");
		lua_pushinteger(L, m->mnt_freq);
		lua_setfield(L, -2, "freq");
		lua_pushinteger(L, m->mnt_passno);
		lua_setfield(L, -2, "passno");
		lua_rawseti(L, -2, c+1);
	}
	endmntent(mtab);
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

