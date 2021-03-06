# NS Programming Assignment : Secure File Transfer
### 50-005 Computer Structures Engineering 2017
#### Jonathan Bei & Ruth Wong


In this project, we have implemented a secure file upload application from a client to an Internet file server using TCP sockets.
To ensure the security of the upload, we: 

1. **authenticated** the identity of the file server, and
2. encrypted the file to keep the data **confidential**
This protects our client from leaking their data to random entities including criminals and eavesdropping by any curious adversaries.


### Our Programs
To demonstrate the difference in performance between symmetric and asymmetric encryption, we have written two programs CP-1 and CP-2.
The first set ServerCP1 and ClientCP1 makes use of an asymmetric RSA encryption for both certificate and data encryption.
The second set ServerCP2 and ClientCP2 makes use of a symmetric AES encryption for the data, and RSA encryption for the certificate.
The performance for each program can be seen in [throughput-plot.pdf](https://github.com/woshibiantai/NS-Programming-Assignment/)


### How to run our program
1. Prepare your private key in your project folder, or use our privateServer.der
2. Get your signed certificate from a Certificate Authority (CA) or use our 1001619.crt, and place it in your project folder, 
3. Put the CA's certificate in your project folder, or use our CA.crt
4. Run the server program first, with the arguments in the following order: Private key path, Signed certificate path, Nonce hashing algorithm

   e.g. `java ServerCP2 privateServer.der 1001619.crt MD5`  
5. The server's IP will be printed. Copy this for use in the client program.
6. Run the client program with the arugments in the following order: CA certificate path, Path of the file to be transferred, The server's IP that has been copied in step 5
  
   e.g. `java ClientCP1 CA.crt sampleData/video.mp4 000.000.0.000`  
7. Wait for the file to be transferred! Successful file transfer will save it in the root folder. 
