#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

int main(int argc, char **argv) {
    
    #pragma region setup
    SSL_library_init(); 
    SSL_load_error_strings(); 
    OpenSSL_add_all_algorithms(); 

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    int  sockfd, n; 
    char buff[256];
    struct sockaddr_in servaddr;

	if(argc!=3){
		printf("Usage : ./cli <IP address> <port>");
		exit(1); 
	}
    
    /* Create a TCP socket */
	if((sockfd=socket(AF_INET,SOCK_STREAM, 0)) < 0){
		perror("socket"); exit(2);}

	
    /* Specify server�s IP address and port */
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(atoi(argv[2])); /* daytime server port */


    if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0) {
        char ip_address[16];
        struct hostent *host_entry = gethostbyname(argv[1]);
        struct in_addr **addr_list = (struct in_addr **)host_entry->h_addr_list;
        servaddr.sin_addr = *addr_list[0];
    }

	/* Connect to the server */
    if (connect(sockfd,  (struct sockaddr *) &servaddr,sizeof(servaddr)) < 0 ) {
        perror("connect"); exit(4); }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    SSL_connect(ssl);
    printf("past connection\n");
    #pragma endregion setup
    // authenticate before main loop
    for (;;) {
        char cred[100]; 
        char response[4];
        printf("Format: <user> <password>\nEnter: ");
        fgets(cred, sizeof(cred), stdin);
        SSL_write(ssl, cred, sizeof(cred)); // 
        SSL_read(ssl, response, sizeof(response)); //
        //printf("server response: %c\n", response);
        if (atoi(&response[0]) == 0) {
            printf("The ID or password is incorrect.\n");
        } else {
            //printf("received success from server\n");
            break;
        }
    }

    for (;;) { // one connection
        printf("sftp> ");

        bzero(buff, 256); // get user command
        fgets(buff, 255, stdin);
        if (strcmp("lls\n", buff) == 0) { // handle lls
            char command[50];
            strcpy(command, "ls");
            system(command);
            continue;  // don't write, restart loop
        }
        SSL_write(ssl, buff, strlen(buff)); // write to server

        if (strcmp("ls\n", buff) == 0) { // ls - looping read special case
            SSL_read(ssl, buff, 255);
            while (strncmp(buff, "lsFinished", 10) != 0) {
                printf("%s", buff);
                bzero(buff, 256);
                SSL_read(ssl, buff, 255);
            }
            continue;
        }

        if (strncmp("get", buff, 3) == 0) { // get - looping read special case
            
            char getBuff[256];
            SSL_read(ssl, getBuff, 255);
            if (strncmp(getBuff, "fileComing", 10) == 0) { // receive SOF signal
        
                bzero(getBuff, sizeof(getBuff));
                SSL_read(ssl, getBuff, sizeof(getBuff)); // receive filename
                FILE * newFile = fopen(getBuff, "w"); // open new file <filename>

                char temp[1024];
                size_t bytes = SSL_read(ssl, temp, sizeof(temp)); // begin reading data from socket
                while (strncmp(temp, "getFinished", 11) != 0) {
                
                    fwrite(temp, 1, bytes, newFile);
                    bzero(temp, 256);
                    bytes = SSL_read(ssl, temp, sizeof(temp));
                }
                fclose(newFile);
                printf("The file is received.\n");
            } else {
                // file wasn't found
                printf("The file does not exist.\n");
            }
            continue;
        }

        char tempComm[256];
        strcpy(tempComm, buff); // save command for comparisons

        SSL_read(ssl, buff, 255);  // general receive server response and print

        if (strncmp("cd", tempComm, 2) == 0) { // "cd" return code
            if (atoi(buff) == 1) {strcpy(buff, "The request action is successful.\n");}
            else {strcpy(buff, "The directory does not exist.\n");}
        }
        /*if (strncmp("get", tempComm, 3) == 0) { // "get" return code
            if (atoi(buff) == 0) {strcpy(buff, "The file does not exist.\n");}
        }*/

        printf("%s", buff); // print buff to console

        char subbuff[19]; // close connection when server confirms exit request
        memcpy(subbuff, buff, 18);
        subbuff[18] = '\0';
        if (strcmp(subbuff, "closing connection") == 0) {
            close(sockfd);
            break;
        }
    }
    SSL_shutdown(ssl); // openSSL cleanup
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}