#include<stdio.h>
#include <stdlib.h>

// {"s":{"length": 4}}
int main(int argc, char **argv) {
    int symvar = argv[1][0] - 48;
    float a = symvar/70.0;
    float b = 0.1;
    if(a != 0.1){
        if(a - b == 0)
            return 1;
    }
    return 0;
}
