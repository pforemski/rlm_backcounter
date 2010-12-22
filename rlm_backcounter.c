/*
 * rlm_backcounter.c
 * Implements monthly transfer limits (and more)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Author: Pawel Foremski <pawel@foremski.pl>
 * Copyright (c) 2010      Pawel Foremski <pawel@foremski.pl>
 *               2007-2009 ASN Sp. z o.o. <http://www.asn.pl/>
 *               2000-2009 The FreeRADIUS server project
 *
 * Current bugs/limits:
 * - probably works only with MySQL
 * - it's too bit "hardcoded"
 *   - queries and table names are not configurable
 *   - access to user attributes is too low-level
 * - handles only at most 32-bit counters for single session (but "any" size in db)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/conffile.h>
#include <freeradius-devel/modpriv.h>

#include "../rlm_sql/rlm_sql.h"

#define RLM_BC_VERSION "0.2"

#define RLM_BC_MAX_ROWS 1000000
#define RLM_BC_TMP_PREFIX "auth-tmp-"

struct bcnt_level {
	uint32_t   from;            /* UNIX timestamp reference point */
	uint32_t   each;            /* number of seconds between repetitions */
	uint32_t   length;          /* number of seconds of how long level lasts */
	double     factor;          /* factor for count_names (see config file) */
	struct bcnt_level *next;    /* next on list */
};

typedef struct rlm_backcounter_t {
	const char *myname;         /* name of this instance */
	SQL_INST *sqlinst;          /* SQL_INST for requested instance */
	rlm_sql_module_t *db;       /* here the fun takes place ;-) */

	/* from config */
	char *sqlinst_name;         /* rlm_sql instance to use */
	int period;                 /* leftvap counter reset period, in seconds */
	int prepaidfirst;           /* if true prepaidvap is be decreased first */
	int noreset;                /* if true don't do any counter resets */

	char *count_names;          /* attributes to count values of, sep with "," */
	int *count_attrs;           /* as above, int values */

	char *overvap;              /* add this VAP to *request* if user has exceeded
	                               his limits; if null, then reject access */
	int overvap_attr;           /* int value of overvap */

	char *guardvap;             /* attribute to set to current counters sum
	                               ie. it should make the NAS close user session
	                               when necessary, not to exceed the limits */
	int guardvap_attr;          /* int value of guardvap */
	char *giga_guardvap;        /* same as guardvap but counts 4 gigas (2^32) */
	int giga_guardvap_attr;     /* int value of giga_guardvap */

	/* from database - VAP names */
	char *leftvap;              /* current user counter state (the main counter) */
	char *limitvap;             /* the amount to add to db_left on counter reset */
	char *resetvap;             /* next counter reset time */
	char *prepaidvap;           /* the prepaid counter (we can only decrease it) */

	/* time-dependent levels */
	char *levels_str;           /* string representation of levels */
	struct bcnt_level *levels;  /* parsed levels_str */
} rlm_backcounter_t;

/* char *name, int type,
 * size_t offset, void *data, char *dflt */
static CONF_PARSER module_config[] = {
	{ "sqlinst_name",  PW_TYPE_STRING_PTR,
	  offsetof(rlm_backcounter_t, sqlinst_name),  NULL, "sql" },
	{ "period",        PW_TYPE_INTEGER,
	  offsetof(rlm_backcounter_t, period),        NULL, "2592000" },  /* default: 30 days */
	{ "prepaidfirst",  PW_TYPE_BOOLEAN,
	  offsetof(rlm_backcounter_t, prepaidfirst),  NULL, "yes" },
	{ "noreset",       PW_TYPE_BOOLEAN,
	  offsetof(rlm_backcounter_t, noreset),       NULL, "no" },
	{ "count_names",   PW_TYPE_STRING_PTR,
	  offsetof(rlm_backcounter_t, count_names),   NULL, "Acct-Input-Octets, Acct-Output-Octets" },
	{ "overvap",       PW_TYPE_STRING_PTR,
	  offsetof(rlm_backcounter_t, overvap),       NULL, "Counter-Exceeded" },
	{ "guardvap",      PW_TYPE_STRING_PTR,
	  offsetof(rlm_backcounter_t, guardvap),      NULL, "Session-Octets-Limit" },
	{ "giga_guardvap", PW_TYPE_STRING_PTR,
	  offsetof(rlm_backcounter_t, giga_guardvap), NULL, "" },
	{ "leftvap",       PW_TYPE_STRING_PTR,
	  offsetof(rlm_backcounter_t, leftvap),       NULL, "Counter-Left" },
	{ "limitvap",      PW_TYPE_STRING_PTR,
	  offsetof(rlm_backcounter_t, limitvap),      NULL, "Counter-Limit" },
	{ "resetvap",      PW_TYPE_STRING_PTR,
	  offsetof(rlm_backcounter_t, resetvap),      NULL, "Counter-Reset" },
	{ "prepaidvap",    PW_TYPE_STRING_PTR,
	  offsetof(rlm_backcounter_t, prepaidvap),    NULL, "Counter-Prepaid" },
	{ "levels",        PW_TYPE_STRING_PTR,
	  offsetof(rlm_backcounter_t, levels_str),    NULL, "" },
	{ NULL, -1, 0, NULL, NULL } /* end */
};

struct lp_data {
	enum lp_keyword {
		LK_FROM,
		LK_EACH,
		LK_FOR,
		LK_USE,
		LK_END
	} keyword;
	int32_t value_int;
	double  value_double;
	char    *next;
};

/** Parse part of the levels option
 * @retval 0   parse error
 * @retval 1   success */
static int bcnt_levels_parser(char *ptr, struct lp_data *lp)
{
	char *keyw, *val;

	if (!ptr) {
		lp->keyword = LK_END;
		lp->next = NULL;
		return 1;
	}

	/* search for keyword */
	while (*ptr == ' ')
		ptr++;

	if (!*ptr)
		return 0;
	else if (*ptr == ',') {
		lp->keyword = LK_END;
		lp->next = ptr + 1;
		return 1;
	}

	/* read keyword */
	keyw = ptr;
	while (isalpha(*ptr))
		ptr++;

	if (*ptr != ' ')
		return 0;

	if (strncmp(keyw, "from", 4) == 0)
		lp->keyword = LK_FROM;
	else if (strncmp(keyw, "each", 4) == 0)
		lp->keyword = LK_EACH;
	else if (strncmp(keyw, "for", 3) == 0)
		lp->keyword = LK_FOR;
	else if (strncmp(keyw, "use", 3) == 0)
		lp->keyword = LK_USE;
	else
		return 0;

	/* read value */
	val = ++ptr;
	while (isdigit(*ptr) || *ptr == '.')
		ptr++;

	lp->value_int = atol(val);
	lp->value_double = strtod(val, (char **) NULL);

	if (*ptr)
		lp->next = ptr;
	else
		lp->next = NULL;

	return 1;
}

/** Find current level
 * @param root             first level
 * @param curtime          current UNIX time
 * @param time_left        time left for to next level change
 * @param retval NULL      no special level active
 */
static struct bcnt_level *bcnt_find_level(struct bcnt_level *root, uint32_t curtime, uint32_t *time_left)
{
	struct bcnt_level *level;
	uint32_t session_timeout;
	uint32_t time_in_level;

level_search:
	session_timeout = UINT32_MAX;

	for (level = root; level; level = level->next) {
		/* level not yet active */
		if (level->from > curtime) {
			if (level->from - curtime < session_timeout)
				session_timeout = level->from - curtime;

			continue;
		}

		/* find our "time position" in level definition */
		time_in_level = (curtime - level->from) % level->each;

		/* outside of level? */
		if (time_in_level >= level->length) {
			if (level->each - time_in_level < session_timeout)
				session_timeout = level->each - time_in_level;

			continue;
		}

		/* set session timeout so it finishes on level end */
		session_timeout = level->length - time_in_level;
		break;
	}

	/* dont select a level if there is less than a minute remaining */
	if (session_timeout < 60) {
		curtime += 60;
		goto level_search;
	}

	if (time_left)
		*time_left = session_timeout;

	return level;
}

/** Wrapper around radlog which adds prefix with module and instance name */
static int bcnt_log_detailed(int lvl, const char *file, unsigned int line, const char *fnname,
	rlm_backcounter_t *data, const char *fmt, ...)
{
	va_list ap;
	int r;
	char pfmt[BUFSIZ];

	snprintf(pfmt, sizeof(pfmt), "rlm_backcounter/%s: (%s#%u) %s(): %s",
		data->myname, file, line, fnname, fmt);

	va_start(ap, fmt);
	r = vradlog(lvl, pfmt, ap);
	va_end(ap);

	return r;
}
#define bcnt_log(lvl, ...) bcnt_log_detailed((lvl), __FILE__, __LINE__, __func__, data, __VA_ARGS__)

/** Handy SQL query tool */
static int bcnt_vquery(unsigned int line, rlm_backcounter_t *data,
                       SQLSOCK *sqlsock, const char *fmt, va_list ap)
{
	char query[MAX_QUERY_LEN];

	vsnprintf(query, MAX_QUERY_LEN, fmt, ap);

	if (rlm_sql_query(sqlsock, data->sqlinst, query)) {
		bcnt_log(L_ERR, "query from line %u: %s",
		         line, (const char *)(data->db->sql_error)(sqlsock, data->sqlinst->config));
		return 0;
	}

	return 1;
}

/** Wrapper around bcnt_vquery */
static int bcnt_query(unsigned int line, rlm_backcounter_t *data,
                     SQLSOCK *sqlsock, const char *fmt, ...)
{
	int r;
	va_list ap;

	va_start(ap, fmt);
	r = bcnt_vquery(line, data, sqlsock, fmt, ap);
	va_end(ap);

	return r;
}

/** Handy wrapper around data->db->sql_finish_query() */
static int bcnt_finish(rlm_backcounter_t *data, SQLSOCK *sqlsock)
{
	return (data->db->sql_finish_query)(sqlsock, data->sqlinst->config);
}

/** Executes query and fetches first row
 *
 * @retval -1 no results
 * @retval  0 db error
 * @retval  1 success
 */
static int bcnt_select(unsigned int line, rlm_backcounter_t *data,
                       SQLSOCK *sqlsock, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!bcnt_vquery(line, data, sqlsock, fmt, ap)) {
		va_end(ap);
		return 0;
	}
	va_end(ap);

	if ((data->db->sql_store_result)(sqlsock, data->sqlinst->config)) {
		bcnt_log(L_ERR, "error while saving results of query from line %u", line);
		return 0;
	}

	if ((data->db->sql_num_rows)(sqlsock, data->sqlinst->config) < 1) {
		bcnt_log(L_DBG, "no results in query from line %u", line);
		return -1;
	}

	if ((data->db->sql_fetch_row)(sqlsock, data->sqlinst->config)) {
		bcnt_log(L_ERR, "couldn't fetch row from results of query from line %u", line);
		return 0;
	}

	return 1;
}

/** Frees select results */
static int bcnt_select_finish(rlm_backcounter_t *data, SQLSOCK *sqlsock)
{
	return ((data->db->sql_free_result)(sqlsock, data->sqlinst->config) ||
	         bcnt_finish(data, sqlsock));
}


/** Cleanup stuff */
static int backcounter_detach(void *instance)
{
	rlm_backcounter_t *data;
	struct bcnt_level *level, *next_level;

	if (instance == NULL)
		return 0;

	data = (rlm_backcounter_t *) instance;

	/* (*data) is zeroed on instantiation */
	if (data->sqlinst_name)  free(data->sqlinst_name);
	if (data->count_names)   free(data->count_names);
	if (data->count_attrs)   free(data->count_attrs);
	if (data->leftvap)       free(data->leftvap);
	if (data->limitvap)      free(data->limitvap);
	if (data->resetvap)      free(data->resetvap);
	if (data->prepaidvap)    free(data->prepaidvap);
	if (data->overvap)       free(data->overvap);
	if (data->guardvap)      free(data->guardvap);
	if (data->giga_guardvap) free(data->giga_guardvap);

	/* free levels */
	level = data->levels;
	while (level) {
		next_level = level->next;
		free(level);
		level = next_level;
	}

	free(data);

	return 0;
}

/** Does initialization */
static int backcounter_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_backcounter_t *data;
	module_instance_t *modinst;
	int i, c, l, a;
	struct bcnt_level *last = NULL, *level;
	DICT_ATTR *dattr;
	struct lp_data lp;

	/* set up a storage area for instance data */
	data = rad_malloc(sizeof(*data));
	if (!data) return -1;
	memset(data, 0, sizeof(*data)); /* so backcounter_detach will know what to free */

	/* fail if the configuration parameters can't be parsed */
	if (cf_section_parse(conf, data, module_config) < 0) {
		backcounter_detach(*instance);
		return -1;
	}

	/* save my name */
	data->myname = cf_section_name2(conf);
	if (!data->myname)
		data->myname = "(no name)";

	modinst = find_module_instance(cf_section_find("modules"), (data->sqlinst_name), 1 );
	if (!modinst) {
		bcnt_log(L_ERR, "cannot find module instance named \"%s\"", data->sqlinst_name);
		backcounter_detach(*instance);
		return -1;
	}

	/* check if the given instance is really a rlm_sql instance */
	if (strcmp(modinst->entry->name, "rlm_sql") != 0) {
		bcnt_log(L_ERR, "given instance (%s) is not an instance of the rlm_sql module", data->sqlinst_name);
		backcounter_detach(*instance);
		return -1;
	}

	/* convert count_names to attributes */
	c = 1;
	l = strlen(data->count_names);

	/* convert commas and spaces to \0, count number of attributes in c */
	for (i = 0; i < l; i++) {
		if (data->count_names[i] == ',' || data->count_names[i] == ' ') {
			c++;
			while (i < l && (data->count_names[i] < 'A' || data->count_names[i] > 'Z'))
				data->count_names[i++] = '\0';
		}
	}

	/* parse attribute names into count_attrs array */
	a = 0;
	data->count_attrs = rad_malloc(sizeof(int) * (c + 1));
	if (!data->count_attrs) {
		backcounter_detach(*instance);
		return -1;
	}

	for (i = 0; i < l; ) {
		dattr = dict_attrbyname(data->count_names + i);
		if (dattr == NULL) {
			bcnt_log(L_ERR, "can't parse count_names argument name: %s", data->count_names + i);
			backcounter_detach(*instance);
			return -1;
		}

		data->count_attrs[a++] = dattr->attr;
		if (a == c) break;

		/* advance to next attribute name */
		i += strlen(data->count_names + i);
		while (data->count_names[i] == '\0' && i < l) i++;
	}

	/* array end guard */
	data->count_attrs[a] = 0;

	if (data->overvap && data->overvap[0]) {
		dattr = dict_attrbyname(data->overvap);
		if (dattr == NULL) {
			bcnt_log(L_ERR, "overvap: can't find such attribute: %s", data->overvap);
			backcounter_detach(*instance);
			return -1;
		}
		data->overvap_attr = dattr->attr;
	}
	else {
		data->overvap_attr = 0;
	}

	if (data->guardvap && data->guardvap[0]) {
		dattr = dict_attrbyname(data->guardvap);
		if (dattr == NULL) {
			bcnt_log(L_ERR, "guardvap: can't find such attribute: %s", data->guardvap);
			backcounter_detach(*instance);
			return -1;
		}
		data->guardvap_attr = dattr->attr;
	}
	else {
		data->guardvap_attr = 0;
	}

	if (data->giga_guardvap && data->giga_guardvap[0]) {
		dattr = dict_attrbyname(data->giga_guardvap);
		if (dattr == NULL) {
			bcnt_log(L_ERR, "giga_guardvap: can't find such attribute: %s", data->giga_guardvap);
			backcounter_detach(*instance);
			return -1;
		}
		data->giga_guardvap_attr = dattr->attr;
	}
	else {
		data->giga_guardvap_attr = 0;
	}

	/*
	 * levels
	 */
	if (data->levels_str && *data->levels_str) {
		lp.next = data->levels_str;

		while (lp.next) {
			level = rad_malloc(sizeof(*level));
			if (!level) {
				backcounter_detach(*instance);
				return -1;
			}

			do {
				if (!bcnt_levels_parser(lp.next, &lp)) {
					bcnt_log(L_ERR, "parse error in 'levels' option");
					backcounter_detach(*instance);
					return -1;
				}

				switch (lp.keyword) {
					case LK_FROM: level->from   = lp.value_int; break;
					case LK_EACH: level->each   = lp.value_int; break;
					case LK_FOR:  level->length = lp.value_int; break;
					case LK_USE:  level->factor = lp.value_double; break;
					case LK_END:  break;
				}
			} while (lp.keyword != LK_END);

			bcnt_log(L_DBG, "loaded level from %d each %d for %d use %g\n",
				level->from, level->each, level->length, level->factor);

			if (level->each < level->length) {
				bcnt_log(L_ERR, "level period repetition is smaller than its length");
				backcounter_detach(*instance);
				return -1;
			}

			/* update list */
			if (!data->levels)
				data->levels = level;
			else if (last)
				last->next = level;

			last = level;
		}
	}

	/* save pointers to useful "objects" */
	data->sqlinst = (SQL_INST *) modinst->insthandle;
	data->db = (rlm_sql_module_t *) data->sqlinst->module;

	*instance = data;

	bcnt_log(L_INFO, "rlm_backcounter " RLM_BC_VERSION " initialized");
	return 0;
}

/** Increases main counter on reset, adds proper VAPs depending on counter values */
static int backcounter_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR *vp = NULL, *user;
	SQLSOCK *sqlsock;
	double counter;
	double resetval;
	uint32_t curtime;
	uint32_t rsttime;
	struct bcnt_level *level;
	uint32_t session_timeout;

	rlm_backcounter_t *data = (rlm_backcounter_t *) instance;

	curtime = (uint32_t) time(NULL);

	/* get real username */
	user = request->username;
	if (user == NULL) {
		bcnt_log(L_ERR, "couldn't find real user name");
		return RLM_MODULE_FAIL;
	}

	/* get our database connection */
	sqlsock = sql_get_socket(data->sqlinst);
	if (!sqlsock) {
		bcnt_log(L_ERR, "error while requesting an SQL socket");
		return RLM_MODULE_FAIL;
	}

	/* fetch *resetvap */
	if (!data->noreset)
	switch (bcnt_select(__LINE__, data, sqlsock,
	        "SELECT `Value` FROM `radreply` "
	        "WHERE `UserName` = '%s' AND `Attribute` = '%s' LIMIT 1",
	        user->vp_strvalue, data->resetvap)) {
		case -1: /* no results */
			bcnt_log(L_DBG, "user '%s' has no '%s' attribute set in radreply table",
			         user->vp_strvalue, data->resetvap);
			break;
		case 0: /* db error */
			sql_release_socket(data->sqlinst, sqlsock);
			return RLM_MODULE_FAIL;
		default: /* there *is* reset timer set */
			rsttime = strtoul(sqlsock->row[0], (char **) NULL, 10);
			bcnt_select_finish(data, sqlsock);

			/* if it's reset time */
			if (curtime > rsttime) {
			 	/* set user's leftvap to the value of limitvap (may be in group reply) */
				bcnt_log(L_DBG, "resetting user '%s' counter", user->vp_strvalue);

				/* if <= 0, we won't update db */
				resetval = 0.0;

				/* fetch limitvap from user */
				switch (bcnt_select(__LINE__, data, sqlsock,
				        "SELECT `Value` FROM `radreply` "
				        "WHERE `UserName` = '%s' AND `Attribute` = '%s' LIMIT 1",
				        user->vp_strvalue, data->limitvap)) {
					case -1: /* no results */
						/* fetch limitvap from group */
						switch (bcnt_select(__LINE__, data, sqlsock,
						        "SELECT `radgroupreply`.`value` FROM `radgroupreply`, `usergroup` "
						        "WHERE "
						        	"`usergroup`.`username`  = '%s' AND "
						        	"`usergroup`.`groupname` = `radgroupreply`.`groupname` AND "
						        	"`radgroupreply`.`attribute` = '%s' "
						        "ORDER BY `usergroup`.`priority` "
						        "LIMIT 1",
						        user->vp_strvalue, data->limitvap)) {
							case -1: /* no results */
								break;
							case 0: /* db error */
								sql_release_socket(data->sqlinst, sqlsock);
								return RLM_MODULE_FAIL;
							default:
								resetval = strtod(sqlsock->row[0], (char **) NULL);
								bcnt_log(L_DBG, "using resetval defined in radgroupreply: %.0f", resetval);
								bcnt_select_finish(data, sqlsock);
								break;
						}
						break;
					case 0: /* db error */
						sql_release_socket(data->sqlinst, sqlsock);
						return RLM_MODULE_FAIL;
					default:
						resetval = strtod(sqlsock->row[0], (char **) NULL);
						bcnt_log(L_DBG, "using resetval defined in radreply: %.0f", resetval);
						bcnt_select_finish(data, sqlsock);
						break;
				}

				if (resetval > 0) {
					/* update leftvap in db */
					if (!bcnt_query(__LINE__, data, sqlsock,
					    "UPDATE `radreply` SET `Value` = '%.0f' "
					    "WHERE `UserName` = '%s' AND `Attribute` = '%s' LIMIT 1",
					    resetval, user->vp_strvalue, data->leftvap)) {
						sql_release_socket(data->sqlinst, sqlsock);
						return RLM_MODULE_FAIL;
					}
					bcnt_finish(data, sqlsock);

				 	/* update next reset time (make sure it's greater than current time) */
					while (rsttime < curtime)
						rsttime += data->period;

					bcnt_log(L_DBG, "new reset time for user '%s': %u", user->vp_strvalue, rsttime);

					/* update resetvap in db */
					if (!bcnt_query(__LINE__, data, sqlsock,
					    "UPDATE `radreply` SET `Value` = '%u' "
					    "WHERE `UserName` = '%s' AND `Attribute` = '%s' LIMIT 1",
					    rsttime, user->vp_strvalue, data->resetvap)) {
						sql_release_socket(data->sqlinst, sqlsock);
						return RLM_MODULE_FAIL;
					}
					bcnt_finish(data, sqlsock);
				}
				else {
					bcnt_log(L_INFO, "couldn't fetch resetval although it's reset time: user '%s'",
						user->vp_strvalue);
				}
			}

			break;
	}

	/* fetch sum of *leftvap and *prepaidvap values from user radreply entries */
	switch (bcnt_select(__LINE__, data, sqlsock,
	        "SELECT SUM(`Value`) FROM `radreply` "
	        "WHERE "
	        	"`UserName` = '%s' AND "
	        	"`Attribute` IN ('%s', '%s') LIMIT 1",
	        user->vp_strvalue, data->leftvap, data->prepaidvap)) {
		case -1: /* no results, but should not happen in this query  */
			bcnt_log(L_ERR, "should not happen");
			sql_release_socket(data->sqlinst, sqlsock);
			return RLM_MODULE_NOOP;
		case 0: /* db error */
			sql_release_socket(data->sqlinst, sqlsock);
			return RLM_MODULE_FAIL;
		default:
			if (sqlsock->row && sqlsock->row[0]) {
				counter = strtod(sqlsock->row[0], (char **) NULL);
			}
			else {
				bcnt_log(L_DBG, "user '%s' has no '%s' nor '%s' attributes set in radreply table",
				         user->vp_strvalue, data->leftvap, data->prepaidvap);

				sql_release_socket(data->sqlinst, sqlsock);
				return RLM_MODULE_NOOP;
			}

			bcnt_select_finish(data, sqlsock);
			break;
	}

	/* Handle levels
	 * 1. check if we are in some level, if not: skip this part
	 * 2. multiply counter by the level factor
	 * 3. set session time limit on the moment when the level ends
	 */
	level = bcnt_find_level(data->levels, curtime, &session_timeout);
	if (level) {
		/* update the counter */
		counter /= level->factor;

		/* add session timeout */
		vp = radius_paircreate(request, &request->reply->vps, PW_SESSION_TIMEOUT, PW_TYPE_INTEGER);
		vp->vp_integer = session_timeout;

		bcnt_log(L_DBG, "from %d each %d for %d use %g -> counter=%g, session-timeout=%d\n",
			level->from, level->each, level->length, level->factor,
			counter, session_timeout);
	}

	/* Below code handles four cases:
	 * 1. user is under limit (has some counter left)
	 *   1.1. uses vp to add guardvap to response, or
	 *   1.2. logs a warning msg if guardvap is not configured
	 * 2. user is over limit
	 *   2.1. uses vp to add overvap to request, or
	 *   2.2. rejects access, if overvap is not configured
	 */
	if (counter > 0) { /* under limit */
		if (data->guardvap_attr) {
			/* set guardvap_attr to counter */
			vp = radius_paircreate(request, &request->reply->vps,
			                       data->guardvap_attr, PW_TYPE_INTEGER);

			if (counter > UINT32_MAX) {
				if (data->giga_guardvap_attr) {
					vp->vp_integer = (uint32_t) counter;

					/* set higher bits 32..63 */
					vp = radius_paircreate(request, &request->reply->vps,
					                       data->giga_guardvap_attr, PW_TYPE_INTEGER);
					vp->vp_integer = (uint32_t) (counter / UINT32_MAX);
				} else {
					/* set the maximum possible value */
					vp->vp_integer = UINT32_MAX;
				}
			} else {
				vp->vp_integer = (uint32_t) counter;
			}
		}
		else {
			bcnt_log(L_DBG, "warning: no guardvap attribute set");
		}
	}
	else { /* over limit */
		if (data->overvap_attr) {
			bcnt_log(L_DBG, "user %s is over limit - adding '%s' attribute",
			         user->vp_strvalue, data->overvap);

			/* set overvap_attr to 1 */
			vp = radius_paircreate(request, &request->reply->vps,
			                       data->overvap_attr, PW_TYPE_INTEGER);
			vp->vp_integer = 1;
		}
		else {
			bcnt_log(L_DBG, "user %s is over limit - rejecting access",
			         user->vp_strvalue);

			/* reject access */
			sql_release_socket(data->sqlinst, sqlsock);
			return RLM_MODULE_USERLOCK;
		}
	}

	/* accept user */
	sql_release_socket(data->sqlinst, sqlsock);
	return RLM_MODULE_OK;
}

/** Decreases counters */
static int backcounter_accounting(void *instance, REQUEST *request)
{
	VALUE_PAIR *vp, *user;
	SQLSOCK *sqlsock;
	double sum = 0.0;
	double curleft, curprepaid;
	int i;
	char *vapname;
	double *targetcur;
	uint32_t curtime;
	struct bcnt_level *level;

	rlm_backcounter_t *data = (rlm_backcounter_t *) instance;

	/* react only to PW_STATUS_STOP packets */
	vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE);
	if (!vp) {
		bcnt_log(L_ERR, "couldn't find type of accounting packet");
		return RLM_MODULE_FAIL;
	}
	else if (vp->vp_integer != PW_STATUS_STOP) {
		return RLM_MODULE_NOOP;
	}

	/* get real username */
	user = request->username;
	if (user == NULL) {
		bcnt_log(L_ERR, "couldn't find real user name");
		return RLM_MODULE_FAIL;
	}

	/* connect to database */
	sqlsock = sql_get_socket(data->sqlinst);
	if (!sqlsock) {
		bcnt_log(L_ERR, "couldn't connect to database");
		return RLM_MODULE_FAIL;
	}

	/* fetch *leftvap and *prepaidvap values from user radreply entries */
	for (i = 0, vapname = data->leftvap, targetcur = &curleft; i < 2;
	     vapname = data->prepaidvap, targetcur = &curprepaid, i++) {
		switch (bcnt_select(__LINE__, data, sqlsock,
		        "SELECT `Value` FROM `radreply` "
		        "WHERE `UserName` = '%s' AND `Attribute` = '%s' LIMIT 1",
		        user->vp_strvalue, vapname)) {
			case -1: /* no results */
				bcnt_log(L_DBG, "user %s has no %s attribute set in radreply table",
				         user->vp_strvalue, vapname);
				*targetcur = -0.1;
				break;
			case 0: /* db error */
				sql_release_socket(data->sqlinst, sqlsock);
				return RLM_MODULE_FAIL;
			default: /* ok */
				*targetcur = strtod(sqlsock->row[0], (char **) NULL);
				bcnt_select_finish(data, sqlsock);
				break;
		}
	}

	/* handle special cases */
	if (curleft < 0 && curprepaid < 0) {
		/* handle case when both counters are negative (ie. no limits) */
		bcnt_log(L_DBG, "user %s: nothing to do", user->vp_strvalue);
		sql_release_socket(data->sqlinst, sqlsock);
		return RLM_MODULE_NOOP;
	}
	else if (curleft <= 0 && curprepaid <= 0) {
		/* handle case when both counters are nonpositive (ie. limit reached) */
		bcnt_log(L_INFO, "user %s has already reached his limit!", user->vp_strvalue);
		sql_release_socket(data->sqlinst, sqlsock);
		return RLM_MODULE_NOOP;
	}

	/* sum session counters */
	for (i = 0; data->count_attrs[i]; i++) {
		vp = pairfind(request->packet->vps, data->count_attrs[i]);
		if (!vp) {
			bcnt_log(L_DBG, "couldn't find attribute #%u to subtract from counters",
			         data->count_attrs[i]);
		}
		else {
			/* FIXME: the attribute may not be of "integer" type (check vp->type) */
			sum += vp->vp_integer;
		}
	}

	/*
	 * handle levels
	 */
	curtime = (uint32_t) time(NULL);

	/* subtract Acct-Session-Time */
	vp = pairfind(request->packet->vps, PW_ACCT_SESSION_TIME);
	if (vp) {
		curtime -= vp->vp_integer;
	}

	/* subtract Acct-Delay-Time */
	vp = pairfind(request->packet->vps, PW_ACCT_DELAY_TIME);
	if (vp) {
		curtime -= vp->vp_integer;
	}

	/* get the level that was active at connection start */
	level = bcnt_find_level(data->levels, curtime, NULL);
	if (level) {
		sum *= level->factor;

		bcnt_log(L_DBG, "time=%d -> from %d each %d for %d use %g -> sum=%g\n",
			curtime, level->from, level->each, level->length, level->factor, sum);
	}

	/* select first counter to subtract from */
	targetcur = (data->prepaidfirst) ? &curprepaid : &curleft;

	/* subtract */
	*targetcur -= sum;

	/* handle case when we have to subtract also from the second counter */
	if (*targetcur < 0) {
		if (data->prepaidfirst) {
			curleft += curprepaid; /* add negative value */
			curprepaid = 0.0;
			targetcur = &curleft;
		}
		else {
			curprepaid += curleft; /* add negative value */
			curleft = 0.0;
			targetcur = &curprepaid;
		}

		if (*targetcur < 0) {
			bcnt_log(L_INFO, "user %s has sent %.0f more bytes than he should",
			         user->vp_strvalue, -(*targetcur));
			*targetcur = 0.0;      /* can't be negative */
		}
	}

	/* store new counters in database */
	for (i = 0, vapname = data->leftvap, targetcur = &curleft; i < 2;
	     vapname = data->prepaidvap, targetcur = &curprepaid, i++) {
		if (!bcnt_query(__LINE__, data, sqlsock,
		    "UPDATE `radreply` SET `Value` = '%.0f' "
		    "WHERE `UserName` = '%s' AND `Attribute` = '%s' LIMIT 1",
		    *targetcur, user->vp_strvalue, vapname)) {
			sql_release_socket(data->sqlinst, sqlsock);
			return RLM_MODULE_FAIL;
		}
		bcnt_finish(data, sqlsock);
	}

	sql_release_socket(data->sqlinst, sqlsock);
	return RLM_MODULE_OK;
}

module_t rlm_backcounter = {
	RLM_MODULE_INIT,
	"backcounter",               /* name */
	RLM_TYPE_THREAD_SAFE,        /* type */
	backcounter_instantiate,     /* instantiation */
	backcounter_detach,          /* detach */
	{
		NULL,                    /* authentication */
		backcounter_authorize,   /* authorization */
		NULL,                    /* preaccounting */
		backcounter_accounting,  /* accounting */
		NULL,                    /* checksimul */
		NULL,                    /* pre-proxy */
		NULL,                    /* post-proxy */
		NULL                     /* post-auth */
	}
};
