//
//  main.m
//  SimpleTraceTarget
//
//  Created by Grzegorz Milos on 29/07/2014.
//  Copyright (c) 2014 Grzegorz Miłoś. All rights reserved.
//

void b(void)
{
    usleep(200 * 1000);
}

void a(void)
{
    for(int i=0; i<5; i++) {
        b();
    }
    printf("Cycle\n");
}

void c(int i);
void d(int i)
{
    c(i-1);
}

void c(int i)
{
    if (i > 0) {
        d(i);
    }
}

void breakpoint(void)
{
    a();
    c(1);
}

int main(int argc, const char * argv[])
{
    while(true) {
        breakpoint();
    }
    return 0;
}
