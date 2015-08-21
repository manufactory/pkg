#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

int 
pkg_linux_deb_version_cmp(const char *pkg1, const char *pkg2)
{
        unsigned int epoch1 = 0, epoch2 = 0;

        const char *pos1, *pos2;
        int cnt;
        
        pos1 = strchr(pkg1, ':');

        /* epoch ignored? */
        if (pos1 != NULL)
                epoch1 = strtol(pkg1, NULL, 10);
        else
                pos1 = pkg1;
        

        pos2 = strchr(pkg2, ':');

        if (pos2 != NULL)
                epoch2 = strtol(pkg2, NULL, 10);
        else
                pos2 = pkg2;

        if (epoch1 < epoch2)
                return -1;
        else if (epoch1 > epoch2)
                return 1;


        /* upstream_version (both parts) */
      
        /* while no digit */
        while((isdigit(*pos1) == 0) && isdigit(*pos2) == 0) {
                printf("no\n");

                if (*pos1 == '~' && *pos2 != '~')
                        return -1;
                else if (*pos1 != '~' && *pos2 == '~')
                        return 1;

                if (*pos1 < *pos2)
                        return -1;
                else if (*pos1 > *pos2)
                        return 1;
                pos1++;
                pos2++; 
        }
        
        cnt = 0;

        while (pos1[cnt] != '\0' || pos2[cnt] != '\0') {
 
                cnt++;
                if (pos1[cnt-1] < pos2[cnt-1])
                        return -1;
                else if (pos1[cnt-1] > pos2[cnt-1])
                        return 1;
        }

        return 0;
}

int main (int argc, char **argv) {
        int ret;     
        /* equal */
//        ret = pkg_linux_deb_version_cmp("0.0.17-1", "0.0.17-1");
//        printf("equal: %d\n", ret);
//        
//        ret = pkg_linux_deb_version_cmp("0.0.17-2", "0.0.17-1");
//        printf("smaller:  %d\n", ret);
//        
//        ret = pkg_linux_deb_version_cmp("0.0.17-1", "0.0.17-2");
//        printf("greater:  %d\n", ret);
//        
//        
//        ret = pkg_linux_deb_version_cmp("30~pre9-5", "30~pre9-5");
//        printf("equal: %d\n", ret);
//        
//        ret = pkg_linux_deb_version_cmp("", "30~pre9-5");
//        printf("Asmaller:  %d\n", ret);
//        
//        ret = pkg_linux_deb_version_cmp("30~pre9-5", "30~pre9-8+b1");
//        printf("greater:  %d\n", ret);
//
//        /* wings3d */
//        ret = pkg_linux_deb_version_cmp("1.5.3-2+b1", "1.5.3-2");
//        printf("greater:  %d\n", ret);
//
//        /* from the specification */
//        ret = pkg_linux_deb_version_cmp("~~", "~~a");
//        printf("smaller:  %d\n", ret);
//        
//        ret = pkg_linux_deb_version_cmp("~~a", "");
//        printf("smaller:  %d\n", ret);
//        
//        ret = pkg_linux_deb_version_cmp("", "a");
//        printf("smaller:  %d\n", ret);

        /* epoch */
//        ret = pkg_linux_deb_version_cmp("1:1-14", "2:1-14");
//        printf("smaller:  %d\n", ret);

        ret = pkg_linux_deb_version_cmp(argv[1], argv[2]);
        printf("result: %d\n", ret);

        return -1;
}
