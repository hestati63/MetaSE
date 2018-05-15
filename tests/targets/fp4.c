#include<stdio.h>
#include <stdlib.h>

// {"s":{"length": 4}}
int main(int argc, char **argv) {
    float x = atof(argv[1]);
    x = x/-10000.0;
    if(1024+x == 1024 && x>0)
        return 0;
    else
        return 1;
}
