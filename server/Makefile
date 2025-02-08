sftpserv: ser.c
	gcc -Wall -w ser.c md5.c aes.c -o sftpserv -I/usr/local/ssl/include/ -L/usr/local/ssl/lib -lssl -lcrypto

clean:
	rm sftpserv *.txt fds/ls.txt fds/pwd.txt