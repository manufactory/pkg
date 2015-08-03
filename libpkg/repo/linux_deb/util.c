#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>

#include <archive.h>
#include <archive_entry.h>

#include "pkg.h"
#include "libpkg/private/pkg.h"
#include "libpkg/private/event.h"

#include "util.h"

#ifndef _LOCALBASE
#define _LOCALBASE	"/usr/local"
#endif

/* this is one by one stolen from pkg_add.c probably some kind of linking
 * should be done. */
static const unsigned char litchar[] =
"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void
pkg_add_file_random_suffix(char *buf, int buflen, int suflen)
{
	int nchars = strlen(buf);
	char *pos;
	int r;

	if (nchars + suflen > buflen - 1) {
		suflen = buflen - nchars - 1;
		if (suflen <= 0)
			return;
	}

	buf[nchars++] = '.';
	pos = buf + nchars;

	while(suflen --) {
#ifndef HAVE_ARC4RANDOM
		r = rand() % (sizeof(litchar) - 1);
#else
		r = arc4random_uniform(sizeof(litchar) - 1);
#endif
		*pos++ = litchar[r];
	}

	*pos = '\0';
}

/* end of stolen code */

int
pkg_repo_util_check_gpg(char *file, const char *sigfile, const char *keyring)
{

        char path[MAXPATHLEN];
        pid_t pid = -1;
        int status = -1;

        snprintf(path, sizeof(path), "%s/bin/gpgv2",
                getenv("LOCALBASE") ? getenv("LOCALBASE") : _LOCALBASE
                );
        
        /* check if gnupg is installed and which version to use */
        if (access(path, X_OK) == -1) {
                snprintf(path, sizeof(path), "%s/bin/gpgv",
	                getenv("LOCALBASE") ? getenv("LOCALBASE") : _LOCALBASE
                        );
                /* fallback to security/gpg1 */
                if (access(path, X_OK) != -1) {
                        pkg_emit_errno("access", "security/gnupg2 installed?");
                        return EPKG_FATAL;
                }
        }

        pid = fork();
        
        if (pid == -1) {
                pkg_emit_errno("fork", "");
                return EPKG_FATAL;
        }

        if (pid == 0) { /* child */
                /* syste.... no, just kidding */
                pkg_debug(1, "Executing %s --quiet --keyring %s %s %s",
                         path, keyring, sigfile, file);
                execl(path, "--quiet", "--keyring", keyring, sigfile, file,
                        NULL);

                /* if we get here, something went wrong. */
                pkg_emit_errno("execl", ""); 
                exit(EXIT_FAILURE);
        } else { /* parent */ 
                if (waitpid(pid, &status, 0) == -1) {
                        pkg_emit_errno("waitpid", ""); 
                        return EPKG_FATAL;
                }

                if (WEXITSTATUS(status) == 0) { /* all signatures valid */
                        pkg_debug(1, "All signatures for %s are valid given signature file: %s", file, sigfile);
                        return EPKG_OK;
               } else if (WEXITSTATUS(status) == 1) { /* at least one signature invalid, */
                        pkg_emit_error("At least one gpg-signature of %s "
                                        "is invalid using sigfile: %s. "
                                        "But at lease one is valid.",
                                        file, sigfile);
                        return EPKG_OK;
               }
        }
        pkg_emit_error("No valid signature for %s given signature file %s", file, sigfile); 
        return EPKG_FATAL; /* bad signature */
}

/* pkg_repo_fetch_remote_extract_fd, 
 * pkg_repo_fetch_remote_extract_mmap and
 * pkg_repo_fetch_remote_extract_tmp are too pkg specific for general use.*/

int
pkg_repo_util_extract_fd(int fd, char *filename, char *dest)
{        
        struct archive *a = NULL;
        struct archive_entry *ae = NULL;
        pkg_error_t retcode = EPKG_OK;
        int ret = ARCHIVE_FATAL;

        a = archive_read_new();
        ae = archive_entry_new();

        archive_read_support_filter_all(a);
        archive_read_support_format_raw(a);

        /* 4096 set elsewhere too ... */
        if (archive_read_open_fd(a, fd, 4096) != ARCHIVE_OK) {
                pkg_emit_error("archive_read_open_fd: %s",
                        archive_error_string(a)); 
                retcode = EPKG_FATAL;
                goto cleanup;
        } 

        ret = archive_read_next_header(a, &ae);
        archive_entry_set_pathname(ae, dest);
        pkg_debug(1, "Extracting: %s to %s", filename, dest);
                
        /* TODO: emit progress ticks, via pkg_emit_progress_tick and
         * archive_read_extract_set_progress_callback  */
        if (archive_read_extract(a, ae, EXTRACT_ARCHIVE_FLAGS) != ARCHIVE_OK) {
                pkg_emit_error("archive_read_extract(): %s",
                        archive_error_string(a));
                retcode = EPKG_FATAL;
                goto cleanup;
        }

        if (ret != ARCHIVE_OK && ret != ARCHIVE_EOF) {
                pkg_emit_error("archive_read_next_header(): %s",
                        archive_error_string(a));

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

/* Database funtctions */

//pkg_repo_util_add_pkg(sqlite3 sqlite, struct pkg *pkg) {
//
//
//}
