#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char arr[64];
    char *ptr;

    ptr = getenv("foo");
    if (ptr) {
        snprintf(arr, sizeof(arr), "PATH=%s", ptr);
        printf("%s\n", arr);
    }



    return 0;
}








