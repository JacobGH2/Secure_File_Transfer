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