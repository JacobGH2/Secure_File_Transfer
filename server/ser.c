#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "md5.h"
#include "aes.h"

int BUFFSIZE = 512;
BYTE key[1][16];

// MD5 and AES code from: https://github.com/B-Con/crypto-algorithms/tree/master

int authenticate(char *username, char *password) {
    
    FILE *passFile = fopen("passwd", "r");
    ssize_t read;
    size_t len = 0;
    char line[60]; // check this later
    char * token = NULL;
   
    // if the input user exists, put their hash in fileHash
    int foundFlag = 0;
    char fileHash[33];
    while (fgets(line, sizeof(line), passFile)) {
        line[strcspn(line, "\n")] = '\0';
        char *currUser = strtok(line, " ");
        const char *currHash = strtok(NULL, "");
        if (strcmp(currUser, username) == 0) {
            foundFlag = 1;
            strcpy(fileHash, currHash);
            break;
        }
    }
    if (foundFlag == 0) {
        printf("server rejected username\n");
        return 0;
    } // auth failed
   
    printf("fileHash:%s\n", fileHash);
    //return 1;
    // fileHash now contains string of correct hash
    
    MD5_CTX ctx; // create md5 hash of password
    BYTE buf[16];
    md5_init(&ctx);
    md5_update(&ctx, password, strlen(password));
    md5_final(&ctx, buf);

    char userHashText[16];
    for (int i = 0; i < 16; i++) {
        sprintf(&userHashText[2*i], "%02x", buf[i]);
    }

    printf("userHashText: %s\n", userHashText);

    // AES
  
    WORD key_schedule[60];
    BYTE enc_buffer[128];
    BYTE iv[1][16] = {
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
	};
    //BYTE key[1][16];
    // load key from file
    /*FILE * keyFile = fopen("key", "r");
    char digitBuff[2];
    int i = 0;
    while (fread(digitBuff, sizeof(char), 2, keyFile) > 0) {
        key[0][i] = (BYTE) strtol(digitBuff, NULL, 16);
        i++;
    }
    fclose(keyFile); */
    // checking loop
    for (int i = 0;i<16;i++) {
        printf("%02x ", key[0][i] & 0xff);
    }
    printf("\n");

    aes_key_setup(key[0], key_schedule, 128);

    aes_encrypt_cbc(buf, 16, enc_buffer, key_schedule, 128, iv[0]);

    char userEncHash[128]; // convert hash to a string
    for (int i = 0; i < 16; i++) {
        sprintf(&userEncHash[2*i], "%02x", enc_buffer[i]);
    }

    printf("User encrypted hash: %s\n", userEncHash);

    if (strcmp(userEncHash, fileHash) != 0) {return 0;} // auth failed

    return 1; // auth success
}

int main(int argc, char **argv) {

    FILE * keyFile = fopen("key", "r");
    char digitBuff[2];
    int i = 0;
    while (fread(digitBuff, sizeof(char), 2, keyFile) > 0) {
        key[0][i] = (BYTE) strtol(digitBuff, NULL, 16);
        i++;
    }
    fclose(keyFile);
    
    #pragma region SSLAndSocketSetup

    SSL_library_init(); // openSSL initializaiton
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method()); // setting up context
    SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(1);
    }

    int listenfd, connfd, clilen;
    struct sockaddr_in servaddr, cliaddr;
    char buff[BUFFSIZE];

    /* Create a TCP socket */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);

    int enable = 1;  // allow immediate reuse of socket
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }

	bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port        = htons(atoi(argv[1]));   /* daytime server */

	/* Bind server's address and port to the socket */
    bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));       
	/* Convert socket to a listening socket max 100 pending clients*/
    listen(listenfd, 100); 

   
    for ( ; ; ) {
        /* Wait for client connections and accept them */
	    clilen = sizeof(cliaddr);
        connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);

        SSL *ssl = SSL_new(ctx);  // bind ssl instance to socket
        SSL_set_fd(ssl, connfd);

        SSL_accept(ssl); // perform SSL handshake with client

        int n = 0, i = 0;
        char *token;
        char command[3][50];
        char *key, *value, *filename;
        int auth = 0;

        #pragma endregion SSLAndSocketSetups


        // authentication, checked before main loop
        for(;;) {
            char authBuff[256];
            char username[32];
            BYTE password[32];
            char *one = "1";
            char *zero = "0";
          
            SSL_read(ssl, authBuff, sizeof(authBuff)); //
            sscanf(authBuff, "%s %s", username, password);
            int authResp = authenticate(username, password);
            if (authResp == 1) {
                SSL_write(ssl, "1", sizeof(char)); //
                printf("wrote success to client\n");
                break;
            }

            SSL_write(ssl, "0", sizeof(char)); // auth failed //
            printf("wrote failure to client\n");
        }
         
        for (;;) { // one connection alternates read and writes

            bzero(buff, BUFFSIZE);
            SSL_read(ssl, buff, BUFFSIZE);
            
            token = strtok(buff, " "); // parse command from client
            i = 0;
            while (token) {
                strcpy(command[i], token);
                token = strtok(NULL, " ");
                i++;
            }

            if (strncmp(command[0], "ls", 2) == 0) { // "ls" command
                char command[50];
                strcpy(command, "ls > ls.txt");
                system(command);
                
                FILE * lsFile = fopen("ls.txt", "r");
                char item[100];
                while (fgets(item, sizeof(item), lsFile) != NULL) {
                    if (strncmp(item, "ls.txt", 6) == 0) continue;
                    SSL_write(ssl, item, sizeof(item));
                }
                remove("ls.txt");
                fclose(lsFile);
                
                SSL_write(ssl, "lsFinished", 10);

            } else if (strncmp(command[0], "pwd", 3) == 0) {
                char cwd[100];
                getcwd(cwd, sizeof(cwd));
                strcat(cwd, "\n");
                SSL_write(ssl, cwd, sizeof(cwd));

            } else if (strncmp(command[0], "cd", 2) == 0) {
                char cwd[100];
                getcwd(cwd, sizeof(cwd));

                char dest[200];
                strcpy(dest, cwd);
                strcat(dest, "/");

                command[1][strcspn(command[1], "\n")] = 0;
                strcat(dest, command[1]);

                if (chdir(dest) == 0) { SSL_write(ssl, "1", 1);} 
                else {SSL_write(ssl, "0", 1);}

            } else if (strncmp(command[0], "get", 3) == 0) {
                
                command[1][strcspn(command[1], "\n")] = 0;

                if (access(command[1], F_OK) == 0) { // check if file exists in directory
                    
                    char signal[100];
                    strcpy(signal, "fileComing");
                    SSL_write(ssl, signal, sizeof(signal));
                    bzero(signal, sizeof(signal));
                    strcpy(signal, command[1]);
                    SSL_write(ssl, signal, sizeof(signal)); // signal that file is coming

                    FILE * getFile = fopen(command[1], "r"); // open file to read from
                    char temp[1024];
                    size_t bytes;
                    while (0 < (bytes = fread(temp, 1, sizeof(temp), getFile))) {
                        SSL_write(ssl, temp, bytes);
                    }
                    SSL_write(ssl, "getFinished", 11); // signal end of file

                } else {
                    SSL_write(ssl, "0", 1);
                }

            } else if (strncmp(command[0], "bye", 3) == 0) { // only checks first 4 chars
                SSL_write(ssl, "closing connection", 18);
                break;
            } else {
                SSL_write(ssl, "Unrecognized command\n", 21);
            }
        }
        SSL_shutdown(ssl); // openSSL cleanup
        SSL_free(ssl);
        //SSL_CTX_free(ctx);
    }
}