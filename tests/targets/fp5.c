#include<stdio.h>
#include <stdlib.h>

// {"s":{"length": 4}}
int main(int argc, char **argv) {
    float x = atof(argv[1]);
    x = x/10.0;
    x = x + 0.1;
    x = x * x;
    if (x > 0.1)
        x -= x;
    if(x != 0.02){
        x = x + 7.98;
        if(x == 8)
            return 0;
    }
    return 1;
}
