/* Copyright (c) 2014, Vsevolod Stakhov
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

#include "linux_deb.h"

struct pkg_repo_ops pkg_repo_linux_deb_ops = {
	.type = "debian",
	.init = pkg_repo_linux_deb_init,        /* nothing to change here */
	.access = pkg_repo_linux_deb_access,    /* nothing to change here */
	.open = pkg_repo_linux_deb_open,        /* nothing to change here */
	.create = pkg_repo_linux_deb_create,    /* nothing to change here */
	.close = pkg_repo_linux_deb_close,      /* nothing to change here */
	.update = pkg_repo_linux_deb_update,    /* has been adapted for .deb */
	.query = pkg_repo_linux_deb_query,      /* SQL adapted for .deb scheme */
	.shlib_provided = pkg_repo_linux_deb_shlib_provide, /* not really applicable for .debs */
	.shlib_required = pkg_repo_linux_deb_shlib_require, /* not really applicable for .debs */
	.provided = pkg_repo_linux_deb_provide, /* TODO: needs discussion about SAT */
	.required = pkg_repo_linux_deb_require,/* TODO: needs discussion about SAT */
	.search = pkg_repo_linux_deb_search,    /* adapted */
	.fetch_pkg = pkg_repo_linux_deb_fetch, /* untested, probably no change needed*/
	.mirror_pkg = pkg_repo_linux_deb_mirror, /* not applicable */ 
	.get_cached_name = pkg_repo_linux_deb_get_cached_name, /* untested, probably no change needed*/
	.ensure_loaded = pkg_repo_linux_deb_ensure_loaded, /* TODO */
	.stat = pkg_repo_linux_deb_stat         /* nothing to change here */
};
