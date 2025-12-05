#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#define fmtsize 0x20

__attribute__((constructor)) void ignore_me(){
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void banner(){
    puts("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
    puts("For all my format string haters.");
    puts("(No one likes %n)");
    puts("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=");
}

void printchoices(){
    puts("1. Keep formatting");
    puts("2. Just leave");
    printf(">> ");
}

void getStr(char * str){
    memset(str, 0, fmtsize);
    read(0, str, fmtsize);
}

void curse(char * str, char * key){
    for(int i=0; i<fmtsize; i++){
        char c = str[i];
        str[i] = c ^ key[i];
    }
    for(int i=0; i<fmtsize; i++){
        key[i] = str[i];
    }
}

int main(){
    char str[fmtsize];
    char key[fmtsize];
    int option;

    banner();
    memset(key, 0xff, fmtsize);
    while(1){
        printchoices();
        getStr(str);
        option = atoi(str);
        switch(option){
            case 1:
                getStr(str);
                curse(str,key);
                printf(str);
                break;
            case 2:
                puts("Hope you did something cool...");
                return 0;
            default:
                puts("Invalid option!");
                break;
        }
    }
}
