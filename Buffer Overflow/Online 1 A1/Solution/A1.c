
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int foo(char *str)
{
    int arr[31];
    char buffer[432];

    /* The following statement has a buffer overflow problem */ 
    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv)
{
    char str[643];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), 643, badfile);
    foo(str);

    printf("Try Again\n");
    return 1;
}

