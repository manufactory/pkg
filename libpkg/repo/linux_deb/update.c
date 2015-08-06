/*
 * Copyright (c) 2014, Vsevolod Stakhov
 * Copyright (c) 2012-2014 Baptiste Daroussin <bapt@FreeBSD.org>
 * Copyright (c) 2012 Julien Laffaye <jlaffaye@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/time.h>

#define _WITH_GETLINE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <archive.h>
#include <archive_entry.h>


#include <fcntl.h>
#include <ctype.h>
#include  <sys/utsname.h>

#include "pkg.h"
#include "private/event.h"
#include "private/utils.h"
#include "private/pkgdb.h"
#include "private/pkg.h"
#include "linux_deb.h"
#include "linux_deb_private.h"

//#include "repo/util.h"
#include "util.h"

//////////////////////

static int
pkg_repo_linux_deb_fetch_check_release_file(struct pkg_repo *repo, char *dest_path) {

        char url[MAXPATHLEN];           /* Release (contains checksums) */
        char filepath[MAXPATHLEN];      /* sth. like /var/db/pkg/reponame-Release*/
        char tmp[MAXPATHLEN];           /* temporary path to Release.gpg */
        char *sigfile;
        const char *dbdir = NULL;
        const char *tailing_slash;
        int retcode = EPKG_FATAL;

        dbdir = pkg_object_string(pkg_config_get("PKG_DBDIR"));
        
        /* The Release file has always to be downloaded. For unstable or 
         * experimental repos it may change daily. */
        
        snprintf(filepath, sizeof(filepath), "%s/%s-%s",
                dbdir, pkg_repo_name(repo), DEBIAN_RELASE_FILE);

        pkg_debug(1, "%s", filepath);
        
        // too potential memory-leaky
        //dest_path = strdup(filepath);
        strlcpy(dest_path, filepath, sizeof(dest_path));

        /* delete old one, errors are ignored elsewhere, so I dare too */
        (void) unlink(filepath);

        /* TODO: here no tailing / is assumed. Maybe just use basename(3) */
        tailing_slash = strrchr(pkg_repo_url(repo), '/') + 1;

        /* assembe URL for Release file */
        strlcpy(url, pkg_repo_url(repo),
                strlen(pkg_repo_url(repo)) - strlen(tailing_slash) + 1);
        strncat(url, DEBIAN_RELASE_FILE, sizeof(DEBIAN_RELASE_FILE));
        
        pkg_debug(1, "fetching %s from %s to %s", DEBIAN_RELASE_FILE, url, filepath);

        /* fetch it */
        if (pkg_fetch_file(repo, url, filepath, 0, 0, 0) != EPKG_OK) {
                pkg_emit_error("cannot fetch Debian Release file %s", DEBIAN_RELASE_FILE);
                return EPKG_FATAL;
        }

        /* assumed URL for Release.gpg file and reuse url */
        strlcpy(url, pkg_repo_url(repo),
                strlen(pkg_repo_url(repo)) - strlen(tailing_slash) + 1);
        strncat(url, DEBIAN_RELASE_FILE_SIG, sizeof(DEBIAN_RELASE_FILE_SIG));
        
        snprintf(tmp, sizeof(tmp), "%s/%s.XXXXX",
            getenv("TMPDIR") != NULL ? getenv("TMPDIR") : "/tmp", DEBIAN_RELASE_FILE_SIG);

        sigfile = mktemp(tmp);
        if (sigfile == NULL) {
                pkg_emit_errno("mktemp", ""); 
                return EPKG_FATAL;
        }
        
        pkg_debug(1, "fetching %s from %s to %s", DEBIAN_RELASE_FILE_SIG, url, sigfile);
        if (pkg_fetch_file_tmp(repo, url, sigfile, 0) != EPKG_OK) {
                pkg_emit_error("cannot fetch Debian signature file %s.", DEBIAN_RELASE_FILE_SIG);
                goto cleanup;
                return EPKG_FATAL;
        }

        retcode = pkg_repo_util_check_gpg(filepath, sigfile,
                        pkg_repo_gpg_keyring(repo));
cleanup:
        (void) unlink(sigfile);

        return retcode;
}

/*TODO: Add size parameter to parse and check size, that's cheaper than
 * calculating the hash, if sizes don't match */
static int
pkg_repo_linux_deb_parse_relase_hash(FILE *fp, char *filename, char *hash)
{       
        char buf[BUFSIZ];
        int i;
        rewind(fp);
        
        /* look for available hashes, possible are md5, sha1, sha256 */

        /* For now we just look for SHA-256 hashes */

       /* while (feof(fp) != 0) { <-- this way we could iterate until we find
        * a supported hash. I.e iterate the while file.
        * Unfortunately it starts with the lease preferably hashes
        * (md5, sha1, sha256) */ 
                
                /* jump to SHA256 hashes in file */
                while (fgets(buf, BUFSIZ, fp) != NULL) {
                        if (strcmp(buf, "SHA256:\n") == 0) {
                                break;
                        }
                }
        /* } <-- hash that is */

        if (ferror(fp) != 0) {
                pkg_emit_errno("fgets", "");
                return EPKG_FATAL;
        }

        while (fgets(buf, BUFSIZ, fp) != NULL) {
                if (strstr(buf, filename) != NULL) {
                        /* skip spaces at beginning of line */
                        for(i=0; isspace(buf[i]); i++)
                                ;

                        strlcpy(hash, &buf[i], PKG_DEBIAN_SHA256_HEX_LEN);
                        break;
                }
        }

        if (ferror(fp)) {
                pkg_emit_errno("fgets", "");
                return EPKG_FATAL;
        }
        
        return EPKG_OK;
}

static int
pkg_repo_linux_deb_fetch_check_extract_packages(struct pkg_repo *repo, int *fd, FILE *release_fp) {
        
        char packages_url[MAXPATHLEN]; /* Packages.gz */
 
        /* Name of Packages.gz in Release, should be something
         * like main/binary-amd64/Packages.gz */
        char packages_release[MAXPATHLEN]; 
        char packages_file[MAXPATHLEN];
        char packages_file_extracted[MAXPATHLEN];
        
        char release_hash[PKG_DEBIAN_SHA256_HEX_LEN];
        char *fetched_hash = NULL;

        const char *abi;
        const char *distribution; /* like main, contrib, non-free, ... */
        int ret = EPKG_FATAL;

        /* archive_read_extract() uses sets the fd to the extracted archive 
         * we still need to close the old one */
        //int fd_unextracted = -1;

        /* small TODO: check if size, hash has changed, take infos from existing Release file
         * if yes there's nothing to download. */
        
        abi = strrchr(pkg_object_string(pkg_config_get("ABI")), ':') + 1;
        
        /* assmble URL for Packages.gz */
        if (strcmp(abi, "amd64") == 0) {
            snprintf(packages_url, sizeof(packages_url), "%s/binary-%s/%s",
                pkg_repo_url(repo), abi, DEBIAN_PACKAGES_FILE);
        } else if (strcmp(abi, "i386") == 0) {
            snprintf(packages_url, sizeof(packages_url), "%s/binary-%s/%s",
                pkg_repo_url(repo), abi, DEBIAN_PACKAGES_FILE);
        } else {
                pkg_emit_error("Could not determine ABI.");

                /* nothing to clean so far */
                return EPKG_FATAL;
        }
        
        /* last part of the URL like ../main  */
        distribution = strrchr(pkg_repo_url(repo), '/') + 1;

        /* assmble filename of Packages.gz in Release
         * should be something like main/binary-amd64/Packages.gz */
        snprintf(packages_release, sizeof(packages_release), "%s/binary-%s/%s", 
                distribution, abi, DEBIAN_PACKAGES_FILE);

        /* path to local release file */
        snprintf(packages_file, sizeof(packages_file), "%s/%s.XXXXX",
            getenv("TMPDIR") != NULL ? getenv("TMPDIR") : "/tmp", DEBIAN_PACKAGES_FILE);

        ret = pkg_fetch_file_tmp(repo, packages_url, packages_file, 0);

        if (ret != EPKG_OK) {
                pkg_emit_error("Error fetching %s to %s", packages_url, packages_file);
                goto cleanup;
        }

        *fd = open(packages_file, O_RDONLY);

        if (release_fp == NULL) {
                pkg_emit_errno("open", "");
                goto cleanup;
        }
        
        ret = pkg_repo_linux_deb_parse_relase_hash(release_fp, packages_release,
                release_hash);

        if (ret != EPKG_OK) {
                pkg_emit_error("Error parsing hash for %s in %s.",
                                packages_release, DEBIAN_PACKAGES_FILE);
                goto cleanup;
        }

        fetched_hash = pkg_checksum_fd(*fd, PKG_HASH_TYPE_SHA256_HEX);

        if (fetched_hash == NULL) {
                pkg_emit_error("Error calculating hash for %s", DEBIAN_PACKAGES_FILE);
                goto cleanup;
        }

        /* compare hashes */
        if (strcmp(fetched_hash, release_hash) != 0) {
                pkg_emit_error("Failed checksum for %s", DEBIAN_PACKAGES_FILE);
                goto cleanup;
        }

        /* extract Packages */

        (void)lseek(*fd, 0, SEEK_SET);

        strlcpy(packages_file_extracted, packages_file,
                sizeof(packages_file_extracted));
        pkg_add_file_random_suffix(packages_file_extracted, sizeof(packages_file_extracted), 12);
        
        //fd_unextracted = dup(*fd);
        ret = pkg_repo_util_extract_fd(*fd, packages_file,
                packages_file_extracted);
        

        if (ret != EPKG_OK) {
                goto cleanup;
        }

cleanup:
        free(fetched_hash);
//        close(fd_unextracted);
        
        /* remove zipped original */
        (void) unlink(packages_file);
        
        if (ret != EPKG_OK) {
                (void) unlink(packages_file_extracted);
        }

        return ret;
}

static int
pkg_repo_linux_deb_parse_dependency(struct pkg *pkg, char *line)
{
        char *token;

        char *begin, *pos;
        char *name, *last = NULL, *version;

        struct pkg_dep *dep;

        //TODO: fix to bool or so, this is ugly
        char *has_version;
        int len;

        while((token = strsep(&line, ",")) != NULL) {
                has_version = strrchr(token, ')');
                

                if (has_version != NULL) {
                        pos = strchr(&token[1], ' '); 
                        len = pos - token - 1;
                        name = strndup(&token[1], len);
                } else {
                        name = strdup(token);
                        version = NULL;
                       // continue;
                }

                /* dependency appear twice.
                 * that happens when version constrains are defined like
                 * v_old <= reqired_v < v_new */
                if (last != NULL && strcmp(name, last) == 0) {
                        last = name;
                        continue;
                }

                last = name;
                
                pkg_dep_new(&dep);
                dep->name = name;

                if (has_version == NULL)
                        continue;
                
                dep->version = version;

                printf("name:\"%s\"\n", dep->name);

                //      alternatives = strchr(&token[len + 2], '|');
                //      if (alternatives)

                begin = strchr(&token[len + 2], ' ');
                pos = strchr(&token[len + 2], ')') ;
                len = pos - begin - 1;
                dep->version = strndup(begin + 1, len);
                printf(" version:\"%s\"\n", dep->version);
                HASH_ADD_KEYPTR(hh, pkg->deps, dep->name, strlen(dep->name), dep);
                
        }

        return EPKG_OK;
}

static int
pkg_repo_linux_deb_parse_packages(struct pkg_repo *repo, FILE *fp, sqlite3 *sqlite) {
        int ret = -1;
        char buf[BUFSIZ];

        struct pkg *pkg = NULL;
        struct pkg_dep *dep = NULL;

        char *pos, *pos2;
        char *next;

        int offset = -1;

        struct utsname u;
        char arch[20] = "FreeBSD:";
        char arch_all[20] = "FreeBSD:";
        char *abi;
        char *dver_start;
        char *dver_end;

        int64_t package_id;

//        size_t arch_size;

        /* get ABI */        
        ret = uname(&u);
        if (ret == -1) {
                pkg_emit_errno("uname", "");
                return EPKG_FATAL;
        }
        
        pos = strchr(u.release, '.');

        if (pos == NULL) {
                pkg_emit_error("could not detect OS version.");
                return EPKG_FATAL;
        }
        
        strlcat(arch, u.release, sizeof("FreeBSD:") + pos - u.release);
        strlcpy(arch_all, arch, sizeof(arch_all));
        
        abi = strrchr(pkg_object_string(pkg_config_get("ABI")), ':') + 1;

        /* TODO: abort when debian repo and no prefix set */
        /* fall back on /compat/linux  */
      //  if (pkg->prefix == NULL)
        //        pkg->prefix = strdup("/compat/linux"); // this could be done nicer


        //strlcat(arch, abi, strlen(arch) + strlen(abi));
        snprintf(arch, sizeof(arch), "%s:%s", arch, abi);
        strlcat(arch_all, ":*", strlen(arch) + sizeof(":*"));

        pkg_debug(1, "arch: %s", arch);
        pkg_debug(1, "arch_all: %s", arch_all);

        //strlcpy(&os_version, u.version, pos)        

        /* logically this is just like arch[right size here] */

        /* pos + */
//        arch_size = sizeof("FreeBSD:") + sizeof(char) * ((u.version - pos) +
//                strlen(abi));
//        pkg_debug(1, "as: %d", arch_size);
//        pkg_debug(1, "pos: %d", pos);
//        pkg_debug(1, "pos: %d", u.version);
//        arch = (char *) malloc(arch_size);
//        snprintf(arch, arch_size, "FreeBSD:%s","f");

        pkg_debug(1, "prefix: %s", pkg_repo_prefix(repo));

        ret = fseek(fp, 0, SEEK_SET);

        if (ret == -1) {
                pkg_emit_errno("fseek", "");
                return EPKG_FATAL;
        }

        ret = pkg_new(&pkg, PKG_REMOTE);
        if (ret != EPKG_OK) {
                return EPKG_FATAL;
        }

        /* this loop is way too long */
        while (fgets(buf, BUFSIZ, fp) != NULL) {
                //pkg_debug(1, "WHILE");


                /* packages separated by newline */
                if (buf[0] == '\n') {
                        pkg->prefix = strdup(pkg_repo_prefix(repo));
                        break;
                        ret = pkg_new(&pkg, PKG_REMOTE);
                        if (ret != EPKG_OK) {
                                return EPKG_FATAL;
                        }
                        
                }

                pos = strstr(buf,"Package:"); 
                if (pos != NULL) {
                        /* STRLEN includes \0, so no +1 for blank 
                         * necessary */
                        pos += STRLEN("Package:");
                        pkg->name = strdup(pos);

                        pkg_debug(1, "pkg->name: %s",pkg->name);
                        continue;
                }

                pos = strstr(buf,"Version:"); 
                if (pos != NULL) {
                        pos += STRLEN("Version:");
                        pkg->version = strdup(pos);
                        pkg_debug(1, "pkg->version: %s",pkg->version);
                        continue;
                }

                pos = strstr(buf,"Installed-Size:"); 
                if (pos != NULL) {
                        pos += STRLEN("Installed-Size:");
                        pkg->flatsize = (int64_t) strtoll(pos, NULL, 10);
                        pkg_debug(1, "pkg->is: %ld",pkg->flatsize);
                        continue;
                }

                pos = strstr(buf,"Size:"); 
                if (pos != NULL) {
                        pos += STRLEN("Size:");
                        pkg->pkgsize = (int64_t) strtoll(pos, NULL, 10);
                        pkg_debug(1, "pkg->pkgsize: %ld",pkg->pkgsize);
                        continue;
                }

                pos = strstr(buf,"Maintainer:"); 
                if (pos != NULL) {
                        pos = strchr(buf, '<') + 1;
                        //offset = strlen(buf) - pos - 1;
                        offset = strrchr(buf, '>') - pos;
                        pkg->maintainer = strndup(buf, offset);
                        pkg_debug(1, "pkg->maintainer: %s",pkg->maintainer);
                        continue;
                }

                pos = strstr(buf,"Architecture:"); 
                if (pos != NULL) {
                        /*TODO: maybe report something on non FreeBSD-Systems */
                        if (strstr(buf,"all"))
                                pkg->arch = strdup(arch_all);
                        else
                                pkg->arch = strdup(arch);

                        pkg_debug(1, "pkg->arch: %s",pkg->arch);
                        continue;
                }

                /* there is Pre-Depends too.... */
                if (strncmp(buf, "Depends:", NELEM("Depends:") - 1) == 0) {
                        pos = strstr(buf,"Depends:"); 
                        if (pos != NULL) {
                                pos += STRLEN("Depends:");
                                //pkg_dep_new(&dep);
                                pkg_repo_linux_deb_parse_dependency(
                                        pkg, pos);

//                                next = pos;
//
//                                int c = 0;
//
//                                while(next != NULL && *next != '\n') {
//                                        c++;
//                                        pos2 = strchr(next, ' '); 
//                                        dep->name = strndup(next, pos2 - next);
//
//                                        /* not all dependencies have versions,
//                                         * if yes, it's in parentesis */
//                                        if (pos2[1] == '(') {
//                                                dver_start = strchr(&pos2[1], ' ');
//                                                dver_end = strchr(&pos2[1], ')');
//                                                dep->version = strndup(dver_start + 1
//                                                                , dver_end - dver_start - 1);
//                                                
//                                                /* ',' is always after ) */
//                                                next = dver_end + 1;
//                                                printf("next1: %s,\n", next);
//                                        } else {
//                                                /* otherwhise we have to
//                                                 * search */
//                                                next = strchr(pos2, ',');
//                                                printf("next2: %s,\n", next);
//
//                                        }
//
//                                        pkg_debug(1, "depn: %s", dep->name);
//                                        pkg_debug(1, "depv: %s", dep->version);
//
//                                        if (c == 4)
//                                        break;
//                                }
                        }

                        continue;
                }




                //      pkg->version = strdup(pos);
                //       pkg_debug(1, "pkg->version: %s",pkg->version);


                pos = strstr(buf,"Description:"); 
                if (pos != NULL) {
                        pos += STRLEN("Description:");
                        pkg->comment = strdup(pos);
                        pkg_debug(1, "pkg->comment: %s",pkg->comment);
                        continue;
                }

                pos = strstr(buf,"Homepage:"); 
                if (pos != NULL) {
                        pos += STRLEN("Homepage:");
                        pkg->www = strdup(pos);
                        pkg_debug(1, "pkg->www: %s",pkg->www);
                        continue;
                }

                pos = strstr(buf,"Filename:"); 
                if (pos != NULL) {
                        pos += STRLEN("Filename:");
                        pkg->repopath = strdup(pos);
                        pkg_debug(1, "pkg->repopath: %s",pkg->repopath);
                        continue;
                }

                pos = strstr(buf,"SHA256:"); 
                if (pos != NULL) {
                        pos += STRLEN("SHA256:");
                        pkg->digest = strdup(pos);
                        pkg_debug(1, "pkg->digest: %s",pkg->digest);
                        continue;
                }
        }

                pkg_debug(1,"pd:%s", pkg->digest);
                pkg_debug(1,"pn:%s",pkg->name);
                //belongs to loop actually
                pkg_debug(1, "BEFORE");
ret =                         pkg_repo_linux_deb_run_prstatement(PKG, pkg->name,
                        pkg->version, pkg->comment,/* pkg->desc,*/
                        pkg->arch, pkg->maintainer,
                        pkg->www, pkg->prefix, pkg->pkgsize, pkg->flatsize,
                        pkg->digest, pkg->repopath);

        package_id = sqlite3_last_insert_rowid(sqlite);
        dep = NULL;

        while (pkg_deps(pkg, &dep) == EPKG_OK) {
                if (pkg_repo_linux_deb_run_prstatement(DEPS, dep->name,
                        dep->version, package_id) != SQLITE_DONE) {
                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(DEPS));
                        return (EPKG_FATAL);
                }
        }

                pkg_debug(1, "ret: %d", ret);
                if (ret != SQLITE_DONE) {
                        ERROR_SQLITE(sqlite, "grmbl");
                        goto cleanup;
                }
                pkg_debug(1, "AFTER");

cleanup:
        ;
        struct pkg_dep *v, *vtmp;
        HASH_ITER(hh, pkg->deps, v, vtmp) { 
                 //HASH_DELETE(hh, problem->variables_by_uid, v); 
                 pkg_debug(1, "1:%s", v->name);
        }


        return EPKG_FATAL;       
}


//////////////////////


static int
pkg_repo_linux_deb_init_update(struct pkg_repo *repo, const char *name)
{
        sqlite3 *sqlite;
        const char update_check_sql[] = ""
                                        "INSERT INTO repo_update VALUES(1);";
        const char update_start_sql[] = ""
                                        "CREATE TABLE IF NOT EXISTS repo_update (n INT);";

        /* [Re]create repo */
        unlink(name);
        if (repo->ops->create(repo) != EPKG_OK) {
                pkg_emit_notice("Unable to create repository %s", repo->name);
                return (EPKG_FATAL);
        }
        if (repo->ops->open(repo, R_OK|W_OK) != EPKG_OK) {
                pkg_emit_notice("Unable to open created repository %s", repo->name);
                return (EPKG_FATAL);
        }

        repo->ops->init(repo);

        sqlite = PRIV_GET(repo);

        if(sqlite3_exec(sqlite, update_check_sql, NULL, NULL, NULL) == SQLITE_OK) {
                pkg_emit_notice("Previous update has not been finished, restart it");
                return (EPKG_END);
        }
        else {
                sql_exec(sqlite, update_start_sql);
        }

        return (EPKG_OK);
}

//static int
//pkg_repo_linux_deb_delete_conflicting(const char *origin, const char *version,
//                         const char *pkg_path, bool forced)
//{
//        int ret = EPKG_FATAL;
//        const char *oversion;
//
//        if (pkg_repo_linux_deb_run_prstatement(REPO_VERSION, origin) != SQLITE_ROW) {
//                ret = EPKG_FATAL;
//                goto cleanup;
//        }
//        oversion = sqlite3_column_text(pkg_repo_linux_deb_stmt_prstatement(REPO_VERSION), 0);
//        if (!forced) {
//                switch(pkg_version_cmp(oversion, version)) {
//                case -1:
//                        pkg_emit_error("duplicate package origin: replacing older "
//                                        "version %s in repo with package %s for "
//                                        "origin %s", oversion, pkg_path, origin);
//
//                        if (pkg_repo_linux_deb_run_prstatement(DELETE, origin, origin) !=
//                                                        SQLITE_DONE)
//                                ret = EPKG_FATAL;
//                        else
//                                ret = EPKG_OK;  /* conflict cleared */
//
//                        break;
//                case 0:
//                case 1:
//                        pkg_emit_error("duplicate package origin: package %s is not "
//                                        "newer than version %s already in repo for "
//                                        "origin %s", pkg_path, oversion, origin);
//                        ret = EPKG_END; /* keep what is already in the repo */
//                        break;
//                }
//        }
//        else {
//                if (pkg_repo_linux_deb_run_prstatement(DELETE, origin, origin) != SQLITE_DONE)
//                        ret = EPKG_FATAL;
//
//                ret = EPKG_OK;
//        }
//
//cleanup:
//        sqlite3_reset(pkg_repo_linux_deb_stmt_prstatement(REPO_VERSION));
//
//        return (ret);
//}

//static int
//pkg_repo_linux_deb_add_pkg(struct pkg *pkg, const char *pkg_path,
//                sqlite3 *sqlite, bool forced)
//{
//        int                      ret;
//        struct pkg_dep          *dep      = NULL;
//        struct pkg_option       *option   = NULL;
//        struct pkg_shlib        *shlib    = NULL;
//        struct pkg_provide      *provide  = NULL;
//        struct pkg_strel        *el;
//        struct pkg_kv           *kv;
//        const char              *arch;
//        int64_t                  package_id;
//
//        arch = pkg->abi != NULL ? pkg->abi : pkg->arch;
//
//try_again:
//        if ((ret = pkg_repo_linux_deb_run_prstatement(PKG,
//            pkg->origin, pkg->name, pkg->version, pkg->comment, pkg->desc,
//            arch, pkg->maintainer, pkg->www, pkg->prefix, pkg->pkgsize,
//            pkg->flatsize, (int64_t)pkg->licenselogic, pkg->sum, pkg->repopath,
//            pkg->digest, pkg->old_digest)) != SQLITE_DONE) {
//                if (ret == SQLITE_CONSTRAINT) {
//                        ERROR_SQLITE(sqlite, "grmbl");
//                        switch(pkg_repo_linux_deb_delete_conflicting(pkg->origin,
//                            pkg->version, pkg_path, forced)) {
//                        case EPKG_FATAL: /* sqlite error */
//                                ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(PKG));
//                                return (EPKG_FATAL);
//                                break;
//                        case EPKG_END: /* repo already has newer */
//                                return (EPKG_END);
//                                break;
//                        default: /* conflict cleared, try again */
//                                goto try_again;
//                                break;
//                        }
//                } else {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(PKG));
//                        return (EPKG_FATAL);
//                }
//        }
//        package_id = sqlite3_last_insert_rowid(sqlite);
//
///*      if (pkg_repo_binary_run_prstatement (FTS_APPEND, package_id,
//                        name, version, origin) != SQLITE_DONE) {
//                ERROR_SQLITE(sqlite, pkg_repo_binary_sql_prstatement(FTS_APPEND));
//                return (EPKG_FATAL);
//        }*/
//
//        dep = NULL;
//        while (pkg_deps(pkg, &dep) == EPKG_OK) {
//                if (pkg_repo_linux_deb_run_prstatement(DEPS, dep->origin,
//                    dep->name, dep->version, package_id) != SQLITE_DONE) {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(DEPS));
//                        return (EPKG_FATAL);
//                }
//        }
//
//        LL_FOREACH(pkg->categories, el) {
//                ret = pkg_repo_linux_deb_run_prstatement(CAT1, el->value);
//                if (ret == SQLITE_DONE)
//                        ret = pkg_repo_linux_deb_run_prstatement(CAT2, package_id,
//                            el->value);
//                if (ret != SQLITE_DONE) {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(CAT2));
//                        return (EPKG_FATAL);
//                }
//        }
//
//        LL_FOREACH(pkg->licenses, el) {
//                ret = pkg_repo_linux_deb_run_prstatement(LIC1, el->value);
//                if (ret == SQLITE_DONE)
//                        ret = pkg_repo_linux_deb_run_prstatement(LIC2, package_id,
//                            el->value);
//                if (ret != SQLITE_DONE) {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(LIC2));
//                        return (EPKG_FATAL);
//                }
//        }
//
//        option = NULL;
//        while (pkg_options(pkg, &option) == EPKG_OK) {
//                ret = pkg_repo_linux_deb_run_prstatement(OPT1, option->key);
//                if (ret == SQLITE_DONE)
//                    ret = pkg_repo_linux_deb_run_prstatement(OPT2, option->key,
//                                option->value, package_id);
//                if(ret != SQLITE_DONE) {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(OPT2));
//                        return (EPKG_FATAL);
//                }
//        }
//
//        shlib = NULL;
//        while (pkg_shlibs_required(pkg, &shlib) == EPKG_OK) {
//                ret = pkg_repo_linux_deb_run_prstatement(SHLIB1, shlib->name);
//                if (ret == SQLITE_DONE)
//                        ret = pkg_repo_linux_deb_run_prstatement(SHLIB_REQD, package_id,
//                                        shlib->name);
//                if (ret != SQLITE_DONE) {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(SHLIB_REQD));
//                        return (EPKG_FATAL);
//                }
//        }
//
//        shlib = NULL;
//        while (pkg_shlibs_provided(pkg, &shlib) == EPKG_OK) {
//                ret = pkg_repo_linux_deb_run_prstatement(SHLIB1, shlib->name);
//                if (ret == SQLITE_DONE)
//                        ret = pkg_repo_linux_deb_run_prstatement(SHLIB_PROV, package_id,
//                                        shlib->name);
//                if (ret != SQLITE_DONE) {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(SHLIB_PROV));
//                        return (EPKG_FATAL);
//                }
//        }
//
//        provide = NULL;
//        while (pkg_provides(pkg, &provide) == EPKG_OK) {
//                ret = pkg_repo_linux_deb_run_prstatement(PROVIDE, provide->provide);
//                if (ret == SQLITE_DONE)
//                        ret = pkg_repo_linux_deb_run_prstatement(PROVIDES, package_id,
//                            provide->provide);
//                if (ret != SQLITE_DONE) {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(PROVIDES));
//                        return (EPKG_FATAL);
//                }
//        }
//
//        provide = NULL;
//        while (pkg_requires(pkg, &provide) == EPKG_OK) {
//                ret = pkg_repo_linux_deb_run_prstatement(REQUIRE, provide->provide);
//                if (ret == SQLITE_DONE)
//                        ret = pkg_repo_linux_deb_run_prstatement(REQUIRES, package_id,
//                            provide->provide);
//                if (ret != SQLITE_DONE) {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(REQUIRES));
//                        return (EPKG_FATAL);
//                }
//        }
//
//        LL_FOREACH(pkg->annotations, kv) {
//                ret = pkg_repo_linux_deb_run_prstatement(ANNOTATE1, kv->key);
//                if (ret == SQLITE_DONE)
//                        ret = pkg_repo_linux_deb_run_prstatement(ANNOTATE1, kv->value);
//                if (ret == SQLITE_DONE)
//                        ret = pkg_repo_linux_deb_run_prstatement(ANNOTATE2, package_id,
//                                  kv->key, kv->value);
//                if (ret != SQLITE_DONE) {
//                        ERROR_SQLITE(sqlite, pkg_repo_linux_deb_sql_prstatement(ANNOTATE2));
//                        return (EPKG_FATAL);
//                }
//        }
//
//        return (EPKG_OK);
//}

static int
pkg_repo_linux_deb_register_conflicts(const char *origin, char **conflicts,
                int conflicts_num, sqlite3 *sqlite)
{
        const char clean_conflicts_sql[] = ""
                        "DELETE FROM pkg_conflicts "
                        "WHERE package_id = ?1;";
        const char select_id_sql[] = ""
                        "SELECT id FROM packages "
                        "WHERE origin = ?1;";
        const char insert_conflict_sql[] = ""
                        "INSERT INTO pkg_conflicts "
                        "(package_id, conflict_id) "
                        "VALUES (?1, ?2);";
        sqlite3_stmt *stmt = NULL;
        int ret, i;
        int64_t origin_id, conflict_id;

        pkg_debug(4, "pkgdb_repo_register_conflicts: running '%s'", select_id_sql);
        if (sqlite3_prepare_v2(sqlite, select_id_sql, -1, &stmt, NULL) != SQLITE_OK) {
                ERROR_SQLITE(sqlite, select_id_sql);
                return (EPKG_FATAL);
        }

        sqlite3_bind_text(stmt, 1, origin, -1, SQLITE_TRANSIENT);
        ret = sqlite3_step(stmt);

        if (ret == SQLITE_ROW) {
                origin_id = sqlite3_column_int64(stmt, 0);
        }
        else {
                ERROR_SQLITE(sqlite, select_id_sql);
                return (EPKG_FATAL);
        }
        sqlite3_finalize(stmt);

        pkg_debug(4, "pkgdb_repo_register_conflicts: running '%s'", clean_conflicts_sql);
        if (sqlite3_prepare_v2(sqlite, clean_conflicts_sql, -1, &stmt, NULL) != SQLITE_OK) {
                ERROR_SQLITE(sqlite, clean_conflicts_sql);
                return (EPKG_FATAL);
        }

        sqlite3_bind_int64(stmt, 1, origin_id);
        /* Ignore cleanup result */
        (void)sqlite3_step(stmt);

        sqlite3_finalize(stmt);

        for (i = 0; i < conflicts_num; i ++) {
                /* Select a conflict */
                pkg_debug(4, "pkgdb_repo_register_conflicts: running '%s'", select_id_sql);
                if (sqlite3_prepare_v2(sqlite, select_id_sql, -1, &stmt, NULL) != SQLITE_OK) {
                        ERROR_SQLITE(sqlite, select_id_sql);
                        return (EPKG_FATAL);
                }

                sqlite3_bind_text(stmt, 1, conflicts[i], -1, SQLITE_TRANSIENT);
                ret = sqlite3_step(stmt);

                if (ret == SQLITE_ROW) {
                        conflict_id = sqlite3_column_int64(stmt, 0);
                }
                else {
                        ERROR_SQLITE(sqlite, select_id_sql);
                        return (EPKG_FATAL);
                }

                sqlite3_finalize(stmt);

                /* Insert a pair */
                pkg_debug(4, "pkgdb_repo_register_conflicts: running '%s'", insert_conflict_sql);
                if (sqlite3_prepare_v2(sqlite, insert_conflict_sql, -1, &stmt, NULL) != SQLITE_OK) {
                        ERROR_SQLITE(sqlite, insert_conflict_sql);
                        return (EPKG_FATAL);
                }

                sqlite3_bind_int64(stmt, 1, origin_id);
                sqlite3_bind_int64(stmt, 2, conflict_id);
                ret = sqlite3_step(stmt);

                if (ret != SQLITE_DONE) {
                        ERROR_SQLITE(sqlite, insert_conflict_sql);
                        return (EPKG_FATAL);
                }

                sqlite3_finalize(stmt);
        }

        return (EPKG_OK);
}

/*static int
pkg_repo_linux_deb_add_from_manifest(char *buf, sqlite3 *sqlite, size_t len,
                struct pkg_manifest_key **keys, struct pkg **p __unused,
                struct pkg_repo *repo)
{
        int rc = EPKG_OK;
        struct pkg *pkg;

        rc = pkg_new(&pkg, PKG_REMOTE);
        if (rc != EPKG_OK)
                return (EPKG_FATAL);

        pkg_manifest_keys_new(keys);
        rc = pkg_parse_manifest(pkg, buf, len, *keys);
        if (rc != EPKG_OK) {
                goto cleanup;
        }

        if (pkg->digest == NULL || !pkg_checksum_is_valid(pkg->digest, strlen(pkg->digest)))
                pkg_checksum_calculate(pkg, NULL);
        if (pkg->arch == NULL || !is_valid_abi(pkg->arch, true)) {
                rc = EPKG_FATAL;
                pkg_emit_error("repository %s contains packages with wrong ABI: %s",
                        repo->name, pkg->arch);
                goto cleanup;
        }

        free(pkg->reponame);
        pkg->reponame = strdup(repo->name);

        rc = pkg_repo_linux_deb_add_pkg(pkg, NULL, sqlite, true);

cleanup:
        pkg_free(pkg);

        return (rc);
}*/

static void __unused
pkg_repo_linux_deb_parse_conflicts(FILE *f, sqlite3 *sqlite)
{
        size_t linecap = 0;
        ssize_t linelen;
        char *linebuf = NULL, *p, **deps;
        const char *origin, *pdep;
        int ndep, i;
        const char conflicts_clean_sql[] = ""
                        "DELETE FROM pkg_conflicts;";

        pkg_debug(4, "pkg_parse_conflicts_file: running '%s'", conflicts_clean_sql);
        (void)sql_exec(sqlite, conflicts_clean_sql);

        while ((linelen = getline(&linebuf, &linecap, f)) > 0) {
                p = linebuf;
                origin = strsep(&p, ":");
                /* Check dependencies number */
                pdep = p;
                ndep = 1;
                while (*pdep != '\0') {
                        if (*pdep == ',')
                                ndep ++;
                        pdep ++;
                }
                deps = malloc(sizeof(char *) * ndep);
                for (i = 0; i < ndep; i ++) {
                        deps[i] = strsep(&p, ",\n");
                }
                pkg_repo_linux_deb_register_conflicts(origin, deps, ndep, sqlite);
                free(deps);
        }

        free(linebuf);
}

static int
pkg_repo_linux_deb_update_proceed(const char *name, struct pkg_repo *repo,
        time_t *mtime, bool force)
{
//        struct pkg *pkg = NULL;
        int rc = EPKG_FATAL;
        sqlite3 *sqlite = NULL;
        //time_t local_t;
        //bool in_trans = false;

        char tmp[MAXPATHLEN];
        //int fd = -1;

        char release_path[MAXPATHLEN];
        FILE *release_fp;
        int packages_fd = -1;
        FILE *packages_fp = NULL;
	bool in_trans = false;

        pkg_debug(1, "Pkgrepo, begin update of '%s'", name);

        /* In forced mode, ignore mtime */
        if (force)
                *mtime = 0;

        //local_t = *mtime;

        snprintf(tmp, sizeof(tmp), "%s/%s.XXXXX",
            getenv("TMPDIR") != NULL ? getenv("TMPDIR") : "/tmp", "Packages.gz");

        /* maybe it would be nicer to rewrite this function, so the
         * file pointer gets only opened once. At the moment it is closed
         * inside and opened again right afterwards for parsing */
        pkg_repo_linux_deb_fetch_check_release_file(repo, release_path);

        snprintf(release_path, sizeof(release_path), "%s", "/var/db/pkg/Debian-Release");
        pkg_debug(1, "rrrp: %s", release_path);

        release_fp = fopen(release_path, "r");

        if (release_fp == NULL) {
                pkg_emit_errno("fopen", release_path); 
                return EPKG_FATAL;
        }
        
        //rc = pkg_repo_linux_deb_fetch_check_extract_packages(repo, &packages_fd, release_fp);

//        if (rc != EPKG_OK) {
//                goto cleanup;
//        }

        packages_fd = open("/tmp/Packages", O_RDONLY);

        packages_fp = fdopen(packages_fd, "r");

        pkg_debug(1, "fuck");

        if (packages_fp == NULL) {
                pkg_emit_errno("fdopen", "");
                goto cleanup;
        }
        pkg_debug(1, "fuck2");

/* stolen code that can stay */
      /* Load local repository data */
      rc = pkg_repo_linux_deb_init_update(repo, name);
      if (rc != EPKG_OK) {
              rc = EPKG_FATAL;
              goto cleanup;
      }


//      /* Here sqlite is initialized */
      sqlite = PRIV_GET(repo);

      pkg_debug(1, "Pkgrepo, reading new packagesite.yaml for '%s'", name);

      pkg_emit_progress_start("Processing entries");

      sql_exec(sqlite, "PRAGMA page_size = %d;", getpagesize());
      sql_exec(sqlite, "PRAGMA cache_size = 10000;");
      sql_exec(sqlite, "PRAGMA foreign_keys = OFF;");

      rc = pkgdb_transaction_begin_sqlite(sqlite, "REPO");
      if (rc != EPKG_OK)
              goto cleanup;

      in_trans = true;

        pkg_repo_linux_deb_parse_packages(repo, packages_fp, sqlite);


        // rc = pkg_repo_linux_deb_parse_packages(sqlite3 *sqlite, packages_fp);


/* stolen code, that can stay: */

      sql_exec(sqlite, ""
//       "INSERT INTO pkg_search SELECT id, name || '-' || version, origin FROM packages;"
//      "CREATE INDEX packages_origin ON packages(origin COLLATE NOCASE);"
      "CREATE INDEX packages_name ON packages(name COLLATE NOCASE);"
//      "CREATE INDEX packages_uid_nocase ON packages(name COLLATE NOCASE, origin COLLATE NOCASE);"
      "CREATE INDEX packages_version_nocase ON packages(name COLLATE NOCASE, version);"
//      "CREATE INDEX packages_uid ON packages(name, origin);"
      "CREATE INDEX packages_version ON packages(name, version);"
//      "CREATE UNIQUE INDEX packages_digest ON packages(manifestdigest);"
       );
cleanup:
        close(packages_fd);
        pkg_debug(1, "fuck3");
 
        /* errors could have happened before, packages_fp is set */
        if (packages_fp != NULL)
                fclose(packages_fp);
        pkg_debug(1, "fuck the hell");

      if (in_trans) {
              pkg_debug(1, "in trans");
              if (rc != EPKG_OK) {
                      pkg_debug(1, "epkg ok");
                      pkgdb_transaction_rollback_sqlite(sqlite, "REPO");
                }

              if (pkgdb_transaction_commit_sqlite(sqlite, "REPO") != EPKG_OK) {
                      pkg_debug(1, "epkg ok2");
                      rc = EPKG_FATAL;
                }
      }

      //pkg_free(pkg);

        return (rc); 
}

int
pkg_repo_linux_deb_update(struct pkg_repo *repo, bool force)
{

        char filepath[MAXPATHLEN];
        const char update_finish_sql[] = ""
                "DROP TABLE repo_update;";
        sqlite3 *sqlite;

        const char *dbdir = NULL;
        struct stat st;
        time_t t = 0;
        int res = EPKG_FATAL;

        bool got_meta = false;

        sqlite3_initialize();

        if (!pkg_repo_enabled(repo))
                return (EPKG_OK);

        dbdir = pkg_object_string(pkg_config_get("PKG_DBDIR"));
        pkg_debug(1, "PkgRepo: verifying update for %s", pkg_repo_name(repo));

        /* First of all, try to open and init repo and check whether it is fine */
        if (repo->ops->open(repo, R_OK|W_OK) != EPKG_OK) {
                pkg_debug(1, "PkgRepo: need forced update of %s", pkg_repo_name(repo));
                t = 0;
                force = true;
                snprintf(filepath, sizeof(filepath), "%s/%s", dbdir,
                    pkg_repo_linux_deb_get_filename(pkg_repo_name(repo)));
        }
        else {
                repo->ops->close(repo, false);
                snprintf(filepath, sizeof(filepath), "%s/%s.meta", dbdir, pkg_repo_name(repo));
                if (stat(filepath, &st) != -1) {
                        t = force ? 0 : st.st_mtime;
                        got_meta = true;
                }

                snprintf(filepath, sizeof(filepath), "%s/%s", dbdir,
                        pkg_repo_linux_deb_get_filename(pkg_repo_name(repo)));
                if (stat(filepath, &st) != -1) {
                        if (!got_meta && !force)
                                t = st.st_mtime;
                }
        }

        res = pkg_repo_linux_deb_update_proceed(filepath, repo, &t, force);
        if (res != EPKG_OK && res != EPKG_UPTODATE) {
                pkg_emit_notice("Unable to update repository %s", repo->name);
                goto cleanup;
        }

        /* Finish updated repo */
        if (res == EPKG_OK) {
                // just commented out not to trigger the assert
                sqlite = PRIV_GET(repo);
                sql_exec(sqlite, update_finish_sql);
        }

cleanup:
        /* Set mtime from http request if possible */
        if (t != 0 && res == EPKG_OK) {
                struct timeval ftimes[2] = {
                        {
                        .tv_sec = t,
                        .tv_usec = 0
                        },
                        {
                        .tv_sec = t,
                        .tv_usec = 0
                        }
                };

                utimes(filepath, ftimes);
                if (got_meta) {
                        snprintf(filepath, sizeof(filepath), "%s/%s.meta", dbdir, pkg_repo_name(repo));
                        utimes(filepath, ftimes);
                }
        }

        if (repo->priv != NULL)
                repo->ops->close(repo, false);

        return (res);
}
