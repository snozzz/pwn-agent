#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greet(const char *name) {
    char buf[64];
    strcpy(buf, name);
    printf("hello %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        greet(argv[1]);
    }
    if (argc > 2) {
        system(argv[2]);
    }
    return 0;
}
