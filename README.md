### Functionality

Once the server executable is running, the client executable can be run. The client will ask for a username and password (valid entries listed below,
enter  as `<username> <password>`).

Once valid credentials are provided, the user will be able to interact with the server through the following client commands:
1.  ```lls``` - print the files in the client's directory.
    
2.   ```ls``` - print the files in the server's directory.
3.  ```get <filename>``` - initiate a transfer of the requested file from the server.
4.  ```cd <directory>``` - change to a different diretory within the server.
5.  ```bye``` - close the connection.

After a connection is closed, the server will continue to run, and running the client executable again will begin a new connection.


### Encryption/Hashing code:

I am using a library created by Brad Conte with basic implementations of MD5 hashing and AES-CBC encryption, which includes the files: aes.c, aes.h, md5.c, and md5.h, which are located in the server subdirectory.

Repository link: https://github.com/B-Con/crypto-algorithms/tree/master

### Execution instructions:

Both sub-directories contain their own Makefiles. With the subdirectory as your current working directory, the command "make" will compile either sftpcli or sftpserv.

These executables can then be run from the command line:

`./sftpcli <server IP/hostname> <server port>` for the client

`./sftpser <server port>` for the server

The client and server may be run on different machines across the same network, but they **MUST** be run with their respective sub-directories as the current working directory.

The usernames and passwords are as follows: 
    
    john 2345
    tim 6780
    bob 1234

The PEM passphrase is "1234".