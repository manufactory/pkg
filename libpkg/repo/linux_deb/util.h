#ifndef UTIL_H_
#define UTIL_H_
int
pkg_repo_util_check_gpg(char *file, const char *sigfile, const char *keyring);

int
pkg_repo_util_extract_fd(int fd, char *filename, char *dest);

void
pkg_add_file_random_suffix(char *buf, int buflen, int suflen);

#endif /* UTIL_H_ */
