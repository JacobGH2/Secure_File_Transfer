sftpcli: cli.c
	gcc -Wall -w -o sftpcli cli.c -I/usr/local/ssl/include/ -L/usr/local/ssl/lib -lssl -lcrypto

c: sftpcli
	./sftpcli 149.125.43.136 7134

clean:
	rm sftpcli