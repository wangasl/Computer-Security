/*
/ file : client.c
/----------------------------------
/ This is a client socket program.
*/

#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#include <netdb.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 7777    
#define MAX_DATA_SIZE 4096
 
int main(int argc, char *argv[])
{
	int sockfd;
	int recvSize;  
	char buff[MAX_DATA_SIZE];
	char sendData[MAX_DATA_SIZE];
	struct sockaddr_in servAddr; 

	if (argc != 2) {
		fprintf(stderr,"Usage: %s <host IP address>\n", argv[0]);
		exit(1);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	servAddr.sin_family = AF_INET;      
	servAddr.sin_port = htons(PORT);    
	servAddr.sin_addr.s_addr = inet_addr(argv[1]);
	bzero(&(servAddr.sin_zero), 8);     

	if (connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) == -1) {
		perror("connect failed");
		exit(1);
	}

	if ((recvSize = recv(sockfd, buff, 30, 0)) == -1) {
		perror("recv failed");
		exit(1);
	}

	buff[recvSize] = '\0';
	printf("%s", buff);

	/* repeat until "exit" input */
	while(1){		printf("Say something: ");
		fgets(sendData, MAX_DATA_SIZE, stdin);

		/* if input is "exit", terminate this program */
		if(!strncmp(sendData, "exit", 4)) break;

		if (send(sockfd, sendData, strlen(sendData), 0) == -1) {
			perror("send failed");
			close(sockfd);
			exit(1);
		}

		if ((recvSize = recv(sockfd, buff, MAX_DATA_SIZE, 0)) == -1) {
			perror("recv failed");
			exit(1);
		}
		buff[recvSize] = '\0';
		printf("You Said: %s\n", buff);
	}
	close(sockfd);

	return 0;
}
