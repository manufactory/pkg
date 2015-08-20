/* Compile with:
 * cc -g -Wall -I ../../ -I ../../../external/sqlite -I ../../../compat/ -I ../../../ -I ../../../external/uthash/ -I ../../../external/libucl/include/ -I ../../../external/libucl/klib/ -l archive add.c -o add
 *
 * What can be enhanced here:
 *
 *  We could easily use 'Section' from the .deb-manifest (Packages) as
 *  category, if desired
 * 
 * --
 * merge mallocs as mentioned in the code
 * 
 * --
 * search in the scripts  user/groups to add it to the db
 * i.e. search for 'adduser --system'
 *
 * https://wiki.debian.org/AccountHandlingInMaintainerScripts
 *
 * --
 * use pkg_emit_progress_tick
 * --
 *
 *
 * */
#include <stdio.h>
#include <string.h>

#include <archive.h>
#include <archive_entry.h>

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <sqlite3.h>

#include "pkg.h"
#include "private/pkg.h"

/* defined in private/pkg.h */
#define EXTRACT_ARCHIVE_FLAGS  (ARCHIVE_EXTRACT_OWNER |ARCHIVE_EXTRACT_PERM | \
		ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_ACL | \
		ARCHIVE_EXTRACT_FFLAGS|ARCHIVE_EXTRACT_XATTR)


/* defined in pkgdb.c */
#define DB_SCHEMA_MAJOR	0
#define DB_SCHEMA_MINOR	32
#define DBVERSION (DB_SCHEMA_MAJOR * 1000 + DB_SCHEMA_MINOR)

/* end of defined somewhere else */

/*
 * compile with in libpkg/repo/linux_deb:
 * cc -I ../../ -I ../../../external/sqlite -l archive add.c -o add
 * */

/* belongs to util.c, but stays here for now to save some messing around
 * with the linker*/

/* push here to ease linking, while developing */


int
pkg_file_new(struct pkg_file **file)
{
	if ((*file = calloc(1, sizeof(struct pkg_file))) == NULL)
		return (EPKG_FATAL);

	(*file)->perm = 0;
	(*file)->fflags = 0;

	return (EPKG_OK);
}

int
pkg_dir_new(struct pkg_dir **d)
{
	if ((*d = calloc(1, sizeof(struct pkg_dir))) == NULL)
		return (EPKG_FATAL);

	(*d)->perm = 0;
	(*d)->fflags = 0;

	return (EPKG_OK);
}

int
pkg_dirs(const struct pkg *pkg, struct pkg_dir **d)
{
	assert(pkg != NULL);

	HASH_NEXT(pkg->dirs, (*d));
}

int
pkg_config_file_new(struct pkg_config_file **c)
{
	if ((*c = calloc(1, sizeof(struct pkg_config_file))) == NULL)
		return (EPKG_FATAL);

	return (EPKG_OK);
}

int
pkg_config_files(const struct pkg *pkg, struct pkg_config_file **f)
{
	assert(pkg != NULL);

	HASH_NEXT(pkg->config_files, (*f));
}

/* end of copied functions */

typedef enum _sql_prstmt_index {
	MTREE = 0,
	PKG,
	DEPS_UPDATE,
	DEPS,
	FILES,
	FILES_REPLACE,
	DIRS1,
	DIRS2,
	CATEGORY1,
	CATEGORY2,
	LICENSES1,
	LICENSES2,
	USERS1,
	USERS2,
	GROUPS1,
	GROUPS2,
	SCRIPT1,
	SCRIPT2,
	OPTION1,
	OPTION2,
	SHLIBS1,
	SHLIBS_REQD,
	SHLIBS_PROV,
	ANNOTATE1,
	ANNOTATE2,
	ANNOTATE_ADD1,
	ANNOTATE_DEL1,
	ANNOTATE_DEL2,
	CONFLICT,
	PKG_PROVIDE,
	PROVIDE,
	FTS_APPEND,
	UPDATE_DIGEST,
	CONFIG_FILES,
	UPDATE_CONFIG_FILE,
	PKG_REQUIRE,
	REQUIRE,
	PRSTMT_LAST,
} sql_prstmt_index;

static sql_prstmt sql_prepared_statements[PRSTMT_LAST] = {
	[MTREE] = {
		NULL,
		"INSERT OR IGNORE INTO mtree(content) VALUES(?1)",
		"T",
	},
	[PKG] = {
		NULL,
		"INSERT OR REPLACE INTO packages( "
			"name, version, comment, message, arch, "
			"maintainer, www, prefix, flatsize, automatic, "
			"mtree_id, time, dep_formula) "
		"VALUES( ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, "
		"?13, (SELECT id FROM mtree WHERE content = ?14), NOW(), ?15, ?16)",
		"TTTTTTTTTTIIITTT",
	},
	[DEPS_UPDATE] = {
		NULL,
		"UPDATE deps SET origin=?1, version=?2 WHERE name=?3;",
		"TTT",
	},
	[DEPS] = {
		NULL,
		"INSERT INTO deps (origin, name, version, package_id) "
		"VALUES (?1, ?2, ?3, ?4)",
		"TTTI",
	},
	[FILES] = {
		NULL,
		"INSERT INTO files (path, md5, package_id) "
		"VALUES (?1, ?2, ?3)",
		"TTI",
	},
	[FILES_REPLACE] = {
		NULL,
		"INSERT OR REPLACE INTO files (path, sha256, package_id) "
		"VALUES (?1, ?2, ?3)",
		"TTI",
	},
	[DIRS1] = {
		NULL,
		"INSERT OR IGNORE INTO directories(path) VALUES(?1)",
		"T",
	},
	[DIRS2] = {
		NULL,
		"INSERT INTO pkg_directories(package_id, directory_id, try) "
		"VALUES (?1, "
		"(SELECT id FROM directories WHERE path = ?2), ?3)",
		"ITI",
	},
	[CATEGORY1] = {
		NULL,
		"INSERT OR IGNORE INTO categories(name) VALUES(?1)",
		"T",
	},
	[CATEGORY2] = {
		NULL,
		"INSERT INTO pkg_categories(package_id, category_id) "
		"VALUES (?1, (SELECT id FROM categories WHERE name = ?2))",
		"IT",
	},
	[LICENSES1] = {
		NULL,
		"INSERT OR IGNORE INTO licenses(name) VALUES(?1)",
		"T",
	},
	[LICENSES2] = {
		NULL,
		"INSERT INTO pkg_licenses(package_id, license_id) "
		"VALUES (?1, (SELECT id FROM licenses WHERE name = ?2))",
		"IT",
	},
	[USERS1] = {
		NULL,
		"INSERT OR IGNORE INTO users(name) VALUES(?1)",
		"T",
	},
	[USERS2] = {
		NULL,
		"INSERT INTO pkg_users(package_id, user_id) "
		"VALUES (?1, (SELECT id FROM users WHERE name = ?2))",
		"IT",
	},
	[GROUPS1] = {
		NULL,
		"INSERT OR IGNORE INTO groups(name) VALUES(?1)",
		"T",
	},
	[GROUPS2] = {
		NULL,
		"INSERT INTO pkg_groups(package_id, group_id) "
		"VALUES (?1, (SELECT id FROM groups WHERE name = ?2))",
		"IT",
	},
	[SCRIPT1] = {
		NULL,
		"INSERT OR IGNORE INTO script(script) VALUES (?1)",
		"T",
	},
	[SCRIPT2] = {
		NULL,
		"INSERT INTO pkg_script(script_id, package_id, type) "
		"VALUES ((SELECT script_id FROM script WHERE script = ?1), "
		"?2, ?3)",
		"TII",
	},
	[OPTION1] = {
		NULL,
		"INSERT OR IGNORE INTO option (option) "
		"VALUES (?1)",
		"T",
	},
	[OPTION2] = {
		NULL,
		"INSERT INTO pkg_option(package_id, option_id, value) "
		"VALUES (?1, "
			"(SELECT option_id FROM option WHERE option = ?2),"
			"?3)",
		"ITT",
	},
	[SHLIBS1] = {
		NULL,
		"INSERT OR IGNORE INTO shlibs(name) VALUES(?1)",
		"T",
	},
	[SHLIBS_REQD] = {
		NULL,
		"INSERT OR IGNORE INTO pkg_shlibs_required(package_id, shlib_id) "
		"VALUES (?1, (SELECT id FROM shlibs WHERE name = ?2))",
		"IT",
	},
	[SHLIBS_PROV] = {
		NULL,
		"INSERT OR IGNORE INTO pkg_shlibs_provided(package_id, shlib_id) "
		"VALUES (?1, (SELECT id FROM shlibs WHERE name = ?2))",
		"IT",
	},
	[ANNOTATE1] = {
		NULL,
		"INSERT OR IGNORE INTO annotation(annotation) "
		"VALUES (?1)",
		"T",
	},
	[ANNOTATE2] = {
		NULL,
		"INSERT OR ROLLBACK INTO pkg_annotation(package_id, tag_id, value_id) "
		"VALUES (?1,"
		" (SELECT annotation_id FROM annotation WHERE annotation = ?2),"
		" (SELECT annotation_id FROM annotation WHERE annotation = ?3))",
		"ITT",
	},
	[ANNOTATE_ADD1] = {
		NULL,
		"INSERT OR IGNORE INTO pkg_annotation(package_id, tag_id, value_id) "
		"VALUES ("
		" (SELECT id FROM packages WHERE name = ?1 ),"
		" (SELECT annotation_id FROM annotation WHERE annotation = ?2),"
		" (SELECT annotation_id FROM annotation WHERE annotation = ?3))",
		"TTTT",
	},
	[ANNOTATE_DEL1] = {
		NULL,
		"DELETE FROM pkg_annotation WHERE "
		"package_id IN"
                " (SELECT id FROM packages WHERE name = ?1) "
		"AND tag_id IN"
		" (SELECT annotation_id FROM annotation WHERE annotation = ?2)",
		"TTT",
	},
	[ANNOTATE_DEL2] = {
		NULL,
		"DELETE FROM annotation WHERE"
		" annotation_id NOT IN (SELECT tag_id FROM pkg_annotation) AND"
		" annotation_id NOT IN (SELECT value_id FROM pkg_annotation)",
		"",
	},
	[CONFLICT] = {
		NULL,
		"INSERT INTO pkg_conflicts(package_id, conflict_id) "
		"VALUES (?1, (SELECT id FROM packages WHERE name = ?2))",
		"IT",
	},
	[PKG_PROVIDE] = {
		NULL,
		"INSERT INTO pkg_provides(package_id, provide_id) "
		"VALUES (?1, (SELECT id FROM provides WHERE provide = ?2))",
		"IT",
	},
	[PROVIDE] = {
		NULL,
		"INSERT OR IGNORE INTO provides(provide) VALUES(?1)",
		"T",
	},
	[FTS_APPEND] = {
		NULL,
		"INSERT OR ROLLBACK INTO pkg_search(id, name, origin) "
		"VALUES (?1, ?2 || '-' || ?3, ?4);",
		"ITTT"
	},
//	[UPDATE_DIGEST] = {
//		NULL,
//		"UPDATE packages SET manifestdigest=?1 WHERE id=?2;",
//		"TI"
//	},
	[CONFIG_FILES] = {
		NULL,
		"INSERT INTO config_files(path, content, package_id) "
		"VALUES (?1, ?2, ?3);",
		"TTI"
	},
	[UPDATE_CONFIG_FILE] = {
		NULL,
		"UPDATE config_files SET content=?1 WHERE path=?2;",
		"TT"
	},
	[PKG_REQUIRE] = {
		NULL,
		"INSERT INTO pkg_requires(package_id, require_id) "
		"VALUES (?1, (SELECT id FROM requires WHERE require = ?2))",
		"IT",
	},
	[REQUIRE] = {
		NULL,
		"INSERT OR IGNORE INTO requires(require) VALUES(?1)",
		"T"
	}
	/* PRSTMT_LAST */
};

static int
pkg_linux_deb_db_init(sqlite3 *sdb)
{
	const char	sql[] = ""
	"BEGIN;"
	"CREATE TABLE packages ("
		"id INTEGER PRIMARY KEY,"
//		"origin TEXT NOT NULL,"
		"name TEXT NOT NULL,"
		"version TEXT NOT NULL,"
		"comment TEXT NOT NULL,"
//		"desc TEXT NOT NULL,"
//		"mtree_id INTEGER REFERENCES mtree(id) ON DELETE RESTRICT"
//			" ON UPDATE CASCADE,"
		"message TEXT,"
		"arch TEXT NOT NULL,"
		"maintainer TEXT NOT NULL, "
		"www TEXT,"
		"prefix TEXT NOT NULL,"
		"flatsize INTEGER NOT NULL,"
		"automatic INTEGER NOT NULL,"
		"locked INTEGER NOT NULL DEFAULT 0,"
//		"licenselogic INTEGER NOT NULL,"
		"time INTEGER, "
		"manifestdigest TEXT NULL, "
//		"pkg_format_version INTEGER,"
//		"dep_formula TEXT NULL"
	");"
//	"CREATE UNIQUE INDEX packages_unique ON packages(name);"
//	"CREATE TABLE mtree ("
//		"id INTEGER PRIMARY KEY,"
//		"content TEXT NOT NULL UNIQUE"
//	");"
	"CREATE TABLE pkg_script ("
		"package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE"
			" ON UPDATE CASCADE,"
		"type INTEGER,"
		"script_id INTEGER REFERENCES script(script_id)"
                        " ON DELETE RESTRICT ON UPDATE CASCADE,"
		"PRIMARY KEY (package_id, type)"
	");"
        "CREATE TABLE script ("
                "script_id INTEGER PRIMARY KEY,"
                "script TEXT NOT NULL UNIQUE"
        ");"
//	"CREATE TABLE option ("
//		"option_id INTEGER PRIMARY KEY,"
//		"option TEXT NOT NULL UNIQUE"
//	");"
//	"CREATE TABLE option_desc ("
//		"option_desc_id INTEGER PRIMARY KEY,"
//		"option_desc TEXT NOT NULL UNIQUE"
//	");"
//	"CREATE TABLE pkg_option ("
//		"package_id INTEGER NOT NULL REFERENCES packages(id) "
//			"ON DELETE CASCADE ON UPDATE CASCADE,"
//		"option_id INTEGER NOT NULL REFERENCES option(option_id) "
//			"ON DELETE RESTRICT ON UPDATE CASCADE,"
//		"value TEXT NOT NULL,"
//		"PRIMARY KEY(package_id, option_id)"
//	");"
//	"CREATE TABLE pkg_option_desc ("
//		"package_id INTEGER NOT NULL REFERENCES packages(id) "
//			"ON DELETE CASCADE ON UPDATE CASCADE,"
//		"option_id INTEGER NOT NULL REFERENCES option(option_id) "
//			"ON DELETE RESTRICT ON UPDATE CASCADE,"
//		"option_desc_id INTEGER NOT NULL "
//			"REFERENCES option_desc(option_desc_id) "
//			"ON DELETE RESTRICT ON UPDATE CASCADE,"
//		"PRIMARY KEY(package_id, option_id)"
//	");"
//	"CREATE TABLE pkg_option_default ("
//		"package_id INTEGER NOT NULL REFERENCES packages(id) "
//			"ON DELETE CASCADE ON UPDATE CASCADE,"
//		"option_id INTEGER NOT NULL REFERENCES option(option_id) "
//			"ON DELETE RESTRICT ON UPDATE CASCADE,"
//		"default_value TEXT NOT NULL,"
//		"PRIMARY KEY(package_id, option_id)"
//	");"
	"CREATE TABLE deps ("
		"origin TEXT NOT NULL,"
		"name TEXT NOT NULL,"
		"version TEXT NOT NULL,"
		"package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE"
			" ON UPDATE CASCADE"
	");"
	"CREATE UNIQUE INDEX deps_unique ON deps(name, version, package_id);"
	"CREATE TABLE files ("
		"path TEXT PRIMARY KEY,"
		"md5 TEXT,"
		"package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE"
			" ON UPDATE CASCADE"
	");"
	"CREATE TABLE directories ("
		"id INTEGER PRIMARY KEY,"
		"path TEXT NOT NULL UNIQUE"
	");"
	"CREATE TABLE pkg_directories ("
		"package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE"
			" ON UPDATE CASCADE,"
		"directory_id INTEGER REFERENCES directories(id) ON DELETE RESTRICT"
			" ON UPDATE RESTRICT,"
		"try INTEGER,"
		"PRIMARY KEY (package_id, directory_id)"
	");"
//	"CREATE TABLE categories ("
//		"id INTEGER PRIMARY KEY,"
//		"name TEXT NOT NULL UNIQUE"
//	");"
	"CREATE TABLE pkg_categories ("
		"package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE"
			" ON UPDATE CASCADE,"
		"category_id INTEGER REFERENCES categories(id) ON DELETE RESTRICT"
			" ON UPDATE RESTRICT,"
		"PRIMARY KEY (package_id, category_id)"
	");"
//	"CREATE TABLE licenses ("
//		"id INTEGER PRIMARY KEY,"
//		"name TEXT NOT NULL UNIQUE"
//	");"
//	"CREATE TABLE pkg_licenses ("
//		"package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE"
//			" ON UPDATE CASCADE,"
//		"license_id INTEGER REFERENCES licenses(id) ON DELETE RESTRICT"
//			" ON UPDATE RESTRICT,"
//		"PRIMARY KEY (package_id, license_id)"
//	");"
	"CREATE TABLE users ("
		"id INTEGER PRIMARY KEY,"
		"name TEXT NOT NULL UNIQUE"
	");"
	"CREATE TABLE pkg_users ("
		"package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE"
			" ON UPDATE CASCADE,"
		"user_id INTEGER REFERENCES users(id) ON DELETE RESTRICT"
			" ON UPDATE RESTRICT,"
		"UNIQUE(package_id, user_id)"
	");"
	"CREATE TABLE groups ("
		"id INTEGER PRIMARY KEY,"
		"name TEXT NOT NULL UNIQUE"
	");"
	"CREATE TABLE pkg_groups ("
		"package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE"
			" ON UPDATE CASCADE,"
		"group_id INTEGER REFERENCES groups(id) ON DELETE RESTRICT"
			" ON UPDATE RESTRICT,"
		"UNIQUE(package_id, group_id)"
	");"
	"CREATE TABLE shlibs ("
		"id INTEGER PRIMARY KEY,"
		"name TEXT NOT NULL UNIQUE"
	");"
	"CREATE TABLE pkg_shlibs_required ("
		"package_id INTEGER NOT NULL REFERENCES packages(id)"
			" ON DELETE CASCADE ON UPDATE CASCADE,"
		"shlib_id INTEGER NOT NULL REFERENCES shlibs(id)"
			" ON DELETE RESTRICT ON UPDATE RESTRICT,"
		"UNIQUE (package_id, shlib_id)"
	");"
	"CREATE TABLE pkg_shlibs_provided ("
		"package_id INTEGER NOT NULL REFERENCES packages(id)"
			" ON DELETE CASCADE ON UPDATE CASCADE,"
		"shlib_id INTEGER NOT NULL REFERENCES shlibs(id)"
			" ON DELETE RESTRICT ON UPDATE RESTRICT,"
		"UNIQUE (package_id, shlib_id)"
	");"
	"CREATE TABLE annotation ("
                "annotation_id INTEGER PRIMARY KEY,"
                "annotation TEXT NOT NULL UNIQUE"
        ");"
        "CREATE TABLE pkg_annotation ("
                "package_id INTERGER REFERENCES packages(id)"
                      " ON DELETE CASCADE ON UPDATE RESTRICT,"
                "tag_id INTEGER NOT NULL REFERENCES annotation(annotation_id)"
                      " ON DELETE CASCADE ON UPDATE RESTRICT,"
		"value_id INTEGER NOT NULL REFERENCES annotation(annotation_id)"
		      " ON DELETE CASCADE ON UPDATE RESTRICT,"
		"UNIQUE (package_id, tag_id)"
	");"
	"CREATE TABLE pkg_conflicts ("
	    "package_id INTEGER NOT NULL REFERENCES packages(id)"
	    "  ON DELETE CASCADE ON UPDATE CASCADE,"
	    "conflict_id INTEGER NOT NULL,"
	    "UNIQUE(package_id, conflict_id)"
	");"
	"CREATE TABLE pkg_lock ("
	    "exclusive INTEGER(1),"
	    "advisory INTEGER(1),"
	    "read INTEGER(8)"
	");"
	"CREATE TABLE pkg_lock_pid ("
	    "pid INTEGER PRIMARY KEY"
	");"
	"INSERT INTO pkg_lock VALUES(0,0,0);"
	"CREATE TABLE provides("
	"    id INTEGER PRIMARY KEY,"
	"    provide TEXT NOT NULL"
	");"
	"CREATE TABLE pkg_provides ("
	    "package_id INTEGER NOT NULL REFERENCES packages(id)"
	    "  ON DELETE CASCADE ON UPDATE CASCADE,"
	    "provide_id INTEGER NOT NULL REFERENCES provides(id)"
	    "  ON DELETE RESTRICT ON UPDATE RESTRICT,"
	    "UNIQUE(package_id, provide_id)"
	");"
	"CREATE TABLE config_files ("
		"path TEXT NOT NULL UNIQUE, "
		"content TEXT, "
		"package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE"
			" ON UPDATE CASCADE"
	");"

	/* FTS search table */

	"CREATE VIRTUAL TABLE pkg_search USING fts4(id, name, origin);"

	/* Mark the end of the array */

	"CREATE INDEX deporigini on deps(origin);"
	"CREATE INDEX pkg_script_package_id ON pkg_script(package_id);"
	"CREATE INDEX deps_package_id ON deps (package_id);"
	"CREATE INDEX files_package_id ON files (package_id);"
	"CREATE INDEX pkg_directories_package_id ON pkg_directories (package_id);"
	"CREATE INDEX pkg_categories_package_id ON pkg_categories (package_id);"
//	"CREATE INDEX pkg_licenses_package_id ON pkg_licenses (package_id);"
	"CREATE INDEX pkg_users_package_id ON pkg_users (package_id);"
	"CREATE INDEX pkg_groups_package_id ON pkg_groups (package_id);"
	"CREATE INDEX pkg_shlibs_required_package_id ON pkg_shlibs_required (package_id);"
	"CREATE INDEX pkg_shlibs_provided_package_id ON pkg_shlibs_provided (package_id);"
	"CREATE INDEX pkg_directories_directory_id ON pkg_directories (directory_id);"
	"CREATE INDEX pkg_annotation_package_id ON pkg_annotation(package_id);"
	"CREATE INDEX pkg_digest_id ON packages(origin, manifestdigest);"
	"CREATE INDEX pkg_conflicts_pid ON pkg_conflicts(package_id);"
	"CREATE INDEX pkg_conflicts_cid ON pkg_conflicts(conflict_id);"
	"CREATE INDEX pkg_provides_id ON pkg_provides(package_id);"
	"CREATE INDEX packages_origin ON packages(origin COLLATE NOCASE);"
	"CREATE INDEX packages_name ON packages(name COLLATE NOCASE);"

	"CREATE VIEW pkg_shlibs AS SELECT * FROM pkg_shlibs_required;"
	"CREATE TRIGGER pkg_shlibs_update "
		"INSTEAD OF UPDATE ON pkg_shlibs "
	"FOR EACH ROW BEGIN "
		"UPDATE pkg_shlibs_required "
		"SET package_id = new.package_id, "
		"  shlib_id = new.shlib_id "
		"WHERE shlib_id = old.shlib_id "
		"AND package_id = old.package_id; "
	"END;"
	"CREATE TRIGGER pkg_shlibs_insert "
		"INSTEAD OF INSERT ON pkg_shlibs "
	"FOR EACH ROW BEGIN "
		"INSERT INTO pkg_shlibs_required (shlib_id, package_id) "
		"VALUES (new.shlib_id, new.package_id); "
	"END;"
	"CREATE TRIGGER pkg_shlibs_delete "
		"INSTEAD OF DELETE ON pkg_shlibs "
	"FOR EACH ROW BEGIN "
		"DELETE FROM pkg_shlibs_required "
                "WHERE shlib_id = old.shlib_id "
		"AND package_id = old.package_id; "
	"END;"

	"CREATE VIEW scripts AS SELECT package_id, script, type"
                " FROM pkg_script ps JOIN script s"
                " ON (ps.script_id = s.script_id);"
        "CREATE TRIGGER scripts_update"
                " INSTEAD OF UPDATE ON scripts "
        "FOR EACH ROW BEGIN"
                " INSERT OR IGNORE INTO script(script)"
                " VALUES(new.script);"
	        " UPDATE pkg_script"
                " SET package_id = new.package_id,"
                        " type = new.type,"
	                " script_id = ( SELECT script_id"
	                " FROM script WHERE script = new.script )"
                " WHERE package_id = old.package_id"
                        " AND type = old.type;"
        "END;"
        "CREATE TRIGGER scripts_insert"
                " INSTEAD OF INSERT ON scripts "
        "FOR EACH ROW BEGIN"
                " INSERT OR IGNORE INTO script(script)"
                " VALUES(new.script);"
	        " INSERT INTO pkg_script(package_id, type, script_id) "
	        " SELECT new.package_id, new.type, s.script_id"
                " FROM script s WHERE new.script = s.script;"
	"END;"
	"CREATE TRIGGER scripts_delete"
	        " INSTEAD OF DELETE ON scripts "
        "FOR EACH ROW BEGIN"
                " DELETE FROM pkg_script"
                " WHERE package_id = old.package_id"
                " AND type = old.type;"
                " DELETE FROM script"
                " WHERE script_id NOT IN"
                         " (SELECT DISTINCT script_id FROM pkg_script);"
	"END;"
	"CREATE VIEW options AS "
		"SELECT package_id, option, value "
		"FROM pkg_option JOIN option USING(option_id);"
	"CREATE TRIGGER options_update "
		"INSTEAD OF UPDATE ON options "
	"FOR EACH ROW BEGIN "
		"UPDATE pkg_option "
		"SET value = new.value "
		"WHERE package_id = old.package_id AND "
			"option_id = ( SELECT option_id FROM option "
				      "WHERE option = old.option );"
	"END;"
	"CREATE TRIGGER options_insert "
		"INSTEAD OF INSERT ON options "
	"FOR EACH ROW BEGIN "
		"INSERT OR IGNORE INTO option(option) "
		"VALUES(new.option);"
		"INSERT INTO pkg_option(package_id, option_id, value) "
		"VALUES (new.package_id, "
			"(SELECT option_id FROM option "
			"WHERE option = new.option), "
			"new.value);"
	"END;"
	"CREATE TRIGGER options_delete "
		"INSTEAD OF DELETE ON options "
	"FOR EACH ROW BEGIN "
		"DELETE FROM pkg_option "
		"WHERE package_id = old.package_id AND "
			"option_id = ( SELECT option_id FROM option "
					"WHERE option = old.option );"
		"DELETE FROM option "
		"WHERE option_id NOT IN "
			"( SELECT DISTINCT option_id FROM pkg_option );"
	"END;"
	"CREATE TABLE requires("
	"    id INTEGER PRIMARY KEY,"
	"    require TEXT NOT NULL"
	");"
	"CREATE TABLE pkg_requires ("
	    "package_id INTEGER NOT NULL REFERENCES packages(id)"
	    "  ON DELETE CASCADE ON UPDATE CASCADE,"
	    "require_id INTEGER NOT NULL REFERENCES requires(id)"
	    "  ON DELETE RESTRICT ON UPDATE RESTRICT,"
	    "UNIQUE(package_id, require_id)"
	");"

	"PRAGMA user_version = %d;"
	"COMMIT;"
	;

	return (sql_exec(sdb, sql, DBVERSION));
 /*	we want this to compile */
 // 	return 0;
}


int
pkg_repo_linux_deb_handle_data(void *buf, int64_t sz, struct pkg *pkg)
{        
        struct archive *a = NULL;
        struct archive_entry *ae = NULL;
        pkg_error_t retcode = EPKG_OK;
        int ret = ARCHIVE_FATAL;

        char dest[MAXPATHLEN];

        struct pkg_dir *dir;

        a = archive_read_new();
        ae = archive_entry_new();

        archive_read_support_filter_all(a);
        archive_read_support_format_all(a);

        if (archive_read_open_memory(a, buf, sz) != ARCHIVE_OK) {
           //     pkg_emit_error("archive_read_open_memory: %s",
           //             archive_error_string(a)); 
                retcode = EPKG_FATAL;
                goto cleanup;
        } 


        while(archive_read_next_header(a, &ae) == ARCHIVE_OK) {

                snprintf(dest, sizeof(dest), "%s/%s", pkg->prefix,
                        archive_entry_pathname(ae) + 2); // <-- skip "./"

                int len = strlen(dest);

                /* are we are dealing with a directory? */
                if (dest[len - 1] == '/') {
                        pkg_dir_new(&dir);
                        strlcpy(dir->path, dest, len);
                
                        HASH_ADD_KEYPTR(hh, pkg->dirs, dir->path,
                        strlen(dir->path), dir);
                }
                        
                archive_entry_set_pathname(ae, dest);
                //printf("pn: %s\n", archive_entry_pathname(ae));
                //pkg_debug(1, "Extracting: to %s", dest);

                /* TODO: emit progress ticks, via pkg_emit_progress_tick and
                 * archive_read_extract_set_progress_callback  */
                if (archive_read_extract(a, ae, EXTRACT_ARCHIVE_FLAGS) != ARCHIVE_OK) {
          //              pkg_emit_error("archive_read_extract(): %s",
          //                              archive_error_string(a));
                    //    retcode = EPKG_FATAL;
                  //      goto cleanup;
                }
        }
        

        if (ret != ARCHIVE_OK && ret != ARCHIVE_EOF) {
           //     pkg_emit_error("archive_read_next_header(): %s",
           //             archive_error_string(a));

                retcode = EPKG_FATAL;
                /* goto cleanup anyway */
        }  

cleanup:
        if (a != NULL) {
                archive_read_close(a);
                archive_read_free(a);
        }
        return retcode;
}


int
pkg_repo_util_extract_mmap()
{

}

int
pkg_linux_deb_read_control(sqlite3 *sqlite, struct pkg *pkg, void *buf, int64_t sz)
{
        struct archive *a = NULL;
        struct archive_entry *ae = NULL;
        pkg_error_t retcode = EPKG_OK;
        int ret = ARCHIVE_FATAL;
        //int fd;
        char *inner, *walk;
        int64_t inner_sz;
        char dest[MAXPATHLEN];
        const char *ae_pathname;

        struct pkg_file *file;
        struct pkg_config_file *config_file;
        char *pos, *eol;
        FILE *fp;


        a = archive_read_new();
        ae = archive_entry_new();

        archive_read_support_filter_all(a);
        archive_read_support_format_all(a);

        /* 4096 set elsewhere too ... */
        if (archive_read_open_memory(a, buf, sz) != ARCHIVE_OK) {
                //     pkg_emit_error("archive_read_open_memory: %s",
                //             archive_error_string(a)); 
                retcode = EPKG_FATAL;
                goto cleanup;
        }

        while(archive_read_next_header(a, &ae) == ARCHIVE_OK) {

                ae_pathname = archive_entry_pathname(ae);
                
                /*
                 * skipt scripts, they are usually _very_ debian specific
                 * */
                if (strcmp(ae_pathname, "postinst") == 0 ||
                        strcmp(ae_pathname, "postrm") == 0 ||
                        strcmp(ae_pathname, "preinst") == 0 ||
                        strcmp(ae_pathname, "prerm") == 0 ||
                        strcmp(ae_pathname, "triggers") == 0 ||
                        strcmp(ae_pathname, "templates") == 0
                        ) {
                        continue;
                }
                
                snprintf(dest, sizeof(dest), "%s/%s", pkg->prefix,
                        archive_entry_pathname(ae) + 2); // <-- skip "./"
                
                inner_sz = archive_entry_size(ae);

                /* if this turns out to be too slow, it is possible to malloc,
                 * the whole archive size, and do a pointer polka here */
                inner = malloc(inner_sz);

                if (inner == NULL) {
                        //pkg_emit_errno("malloc", "");
                        goto cleanup;
                }

                /* skip prepending './' */
                if (strcmp(ae_pathname + 2, "md5sums") == 0) {

                        /* read files here */

                        archive_read_data(a, inner, inner_sz);

                        walk = inner;

                        while (walk - inner < inner_sz) {
                                pkg_file_new(&file);

                                pos = strchr(walk, ' ');
                                file->sum = strndup(walk, pos - walk);
                                //printf("md5sum: %s\n", file->sum);

                                eol = strchr(walk, '\n');

                                snprintf(file->path, sizeof(file->path), "%s/",
                                                pkg->prefix);
                                
                                /* two blanks are seperating, thus + 2 */
                                strlcat(file->path, pos + 2,
                                                eol - pos + strlen(file->path));
                                //printf("path:%s\n", file->path);

                                HASH_ADD_KEYPTR(hh, pkg->files, file->path,
                                                strlen(file->path), file);

                                walk = eol + 1;
                        }
                        continue;
                }

                if (strcmp(ae_pathname + 2, "conffiles") == 0) {
                        archive_read_data(a, inner, inner_sz);

                        walk = inner;

                        while (walk - inner < inner_sz) {
                                pkg_config_file_new(&config_file);

                                eol = strchr(walk, '\n');
                                snprintf(config_file->path,
                                                sizeof(config_file->path), "%s",
                                                pkg->prefix);
                                strlcat(config_file->path, walk, eol - walk +
                                                strlen(config_file->path) + 1);

                                //printf("config file:%s\n", config_file->path);

                                HASH_ADD_KEYPTR(hh, pkg->config_files,
                                                config_file->path,
                                                strlen(config_file->path), config_file);

                                walk = eol + 1;

                        }
                }

                if (strcmp(ae_pathname, "control")) {
                        /* the syntax is exactly Packages syntax, but refactor firxt  */
                        fp = fmemopen(inner, inner_sz, "r");
                        //pkg_repo_linux_deb_parse_packages(pkg->repo, fp, sqlite);
                }

                //pkg_debug(1, "Extracting: to %s", dest);

                free(inner);
        }

        /* after parsing 'control, we have the pkg's id */

        file = NULL;
        /* so add files */
        /*while (pkg_files(pkg, &file) == EPKG_OK) {
                if (pkg_repo_linux_deb_run_prstatement(FILES, file->path,
                                file->sum, pkg->id) != SQLITE_DONE) {
                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(FILES));
                        return (EPKG_FATAL);
                }
        } */

        /* and while we are at it, the directories too */

        if (ret != ARCHIVE_OK && ret != ARCHIVE_EOF) {
                //     pkg_emit_error("archive_read_next_header(): %s",
                //             archive_error_string(a));

                retcode = EPKG_FATAL;
                /* goto cleanup anyway */
        }
cleanup:
        ; 

}

int
pkg_linux_deb_handle_deb(char *path)
{
        struct archive *a = NULL;
        struct archive *inner = NULL;
        struct archive_entry *ae = NULL;
        const char *ae_pathname = NULL;
        int retcode = EPKG_OK;
        int ret = ARCHIVE_FATAL;
        struct pkg *pkg;
        struct pkg_config_file *cf = NULL;
        struct stat sb;

        int64_t sz;
        void *buf;
        int fd;
        ssize_t read_sz;

        //struct pkg_config_file *cf;
        
        /*TODO: mocked! */
        pkg = malloc(sizeof(struct pkg));
        pkg->prefix = strdup("/tmp/dest");
        /* end mocked */


        a = archive_read_new();

        archive_read_support_filter_all(a);
        archive_read_support_format_all(a);

        if (archive_read_open_filename(a, path, 4096) != ARCHIVE_OK) {
        //        pkg_emit_error("archive_read_open_filename: %s",
        //                archive_error_string(a)); 
                retcode = EPKG_FATAL;
                goto cleanup;
        } 

        
        while (archive_read_next_header(a, &ae) == ARCHIVE_OK) {
                ae_pathname = archive_entry_pathname(ae);
                printf("archive_pathname: %s\n", ae_pathname);

                sz = archive_entry_size(ae); 
                printf("archive_size: %ld\n", sz);

                inner = archive_read_new();

                archive_read_support_filter_all(inner);
                archive_read_support_format_all(inner);

                buf = malloc(sz);

                read_sz = archive_read_data(a, buf, sz);

                /* there are by specification several possible endings
                 * e.g. (.gz, .xz) */
                if (strstr(ae_pathname, "data.tar.") != NULL) {
                //        pkg_repo_util_extract_memory(buf, sz, dest);
                        pkg_repo_linux_deb_handle_data(buf, sz, pkg);

                }

                /* here too of course */
                if (strstr(ae_pathname, "control.tar.") != NULL) {
                        pkg_linux_deb_read_control(NULL, pkg,
                                buf, sz);
                }
                free(buf);
        }
        
        struct pkg_dir *dir = NULL;
        while(pkg_dirs(pkg, &dir) == EPKG_OK) {
                printf("dir: %s\n", dir->path);
               /* if (pkg_repo_linux_deb_run_prstatement(DIRS1, dir->path)
                                 != SQLITE_DONE) {
                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(DIRS1));
                        return (EPKG_FATAL);
                }
                if (pkg_repo_linux_deb_run_prstatement(DIRS2, pkg->id, dir->path, 1)
                                 != SQLITE_DONE) {
                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(DIRS2));
                        return (EPKG_FATAL);
                }*/
        }

        /* now we know that all config files are extracted, so put their
         * content into the db! */
        
        cf = NULL;
        while(pkg_config_files(pkg, &cf) == EPKG_OK) {
                
                /* maybe it is useful (even for the new debian-like pakcages)
                 * to safe the config file size, so we don't have to stat()
                 * here. Getting it from the archive is cheaper  */
                if (stat(cf->path, &sb) == -1) {
                        //pkg_emit_errno("stat", "");
                        goto cleanup;
                }

                fd = open(cf->path, O_RDONLY);
                
                if (fd == -1) {
                        //pkg_emit_errno("open", "");
                        goto cleanup;
                }

                /* again, here we could get the malloc() out of the loop,
                 * and dance pointer polka */
                buf = malloc(sb.st_size);

                if (buf == NULL) {
                        //pkg_emit_errno("malloc", "");
                        goto cleanup;
                }

                ret = read(fd, buf, sb.st_size);

                
//                if (pkg_repo_linux_deb_run_prstatement(UPDATE_CONFIG_FILE, buf,
//                                cf->path) != SQLITE_DONE) {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(FILES));
//                        return (EPKG_FATAL);
//                }

                //printf("buffer: %s\n", buf);
                
                /* free/close even in case of an error */
                free(buf);
                close(fd);
                
                if (ret == -1) {
                        //pkg_emit_errno("read", "");
                        goto cleanup;
                }
        }
        
        if (ret != ARCHIVE_OK && ret != ARCHIVE_EOF) {
        //        pkg_emit_error("archive_read_next_header(): %s",
        //                archive_error_string(a));

        //        retcode = EPKG_FATAL;
                /* goto cleanup anyway */
        }

cleanup:
        ret = archive_read_free(a);
 
}

/* mocked */
int
pkg_add_common_linux_deb(sqlite3 *sqlite, char *path, unsigned flags,
        struct pkg_manifest_key *keys, const char *location)
{
        /*arguments:
         * location: keys is always NULL for .debs */


}

int main (int argc, char *args[]) {
        printf("arg1: %s\n", args[1]);        

      pkg_linux_deb_handle_deb(args[1]); 
}
