#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stdint.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <ctype.h>
#include <signal.h>

#define PORT 8080
#define FILE_SIZE 80
#define SA struct sockaddr
#define SIZE 512



void sigint_handler(int sig) {
    printf("Received SIGINT signal\n");
    exit(0);
}


void handleErrors(void)
{
	printf("Something went wrong!\n");
    ERR_print_errors_fp(stderr);
	abort();
}




int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();


    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;


    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;


    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();


    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();


    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;


    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

unsigned char* remove_padd(unsigned char input[]){
	int sz = strlen((char *)input);                      
	for (int i = 0; i < sz; i++) {
        if ( isalnum(input[i]) ){
            continue;
        }
		else{
			input[i] = '\0';
			break;
		}
    }
	return input;
}



int main()
{	
	signal(SIGINT, sigint_handler);

	struct sockaddr_in socketAddressServer, socketAddressClient;

	int socketfiledesc = socket(AF_INET, SOCK_STREAM, 0);
	if( socketfiledesc == -1) {
    	printf("Socket not created");
    	exit(0);
    }

	int rse=1;
	if (setsockopt(socketfiledesc, SOL_SOCKET, SO_REUSEADDR , &rse, sizeof(rse))) {   
        printf("sockopt error");
        exit(0);
    }

	bzero(&socketAddressServer, sizeof(socketAddressServer));

	socketAddressServer.sin_family = AF_INET;
	socketAddressServer.sin_addr.s_addr = htonl(INADDR_ANY);
	socketAddressServer.sin_port = htons(PORT);

	int bnd = bind(socketfiledesc, (SA *)&socketAddressServer, sizeof(socketAddressServer));
	if( bnd != 0) {
    	printf("Not binded");
    	exit(0);
    }

	int lstn = listen(socketfiledesc, 7);
	if( lstn != 0) {
    	printf("Listening not working");
    	exit(0);
    }

	socklen_t size = sizeof(socketAddressClient);

	int socket_commu = accept(socketfiledesc, (SA *)&socketAddressClient, &size);
	if( socket_commu < 0) {
    	printf("Accepting not working");
    	exit(0);
    }


	char init_vec[30];
	int ciphertext_lenchall;
	int ciphertextlbl_len;



	unsigned char ciphertextlbl_dec[SIZE];
	if (recv(socket_commu, ciphertextlbl_dec, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}



	sleep(1);

	unsigned char ciphertext_dec[SIZE];
	if (recv(socket_commu, ciphertext_dec, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}



	sleep(1);

	if (recv(socket_commu, init_vec, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}


	sleep(1);


	char bfr[SIZE];

	if (recv(socket_commu, bfr, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}
	ciphertext_lenchall= atoi(bfr);
	bzero(bfr, SIZE);                  

	sleep(1);


	if (recv(socket_commu, bfr, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}
	ciphertextlbl_len= atoi(bfr);
	bzero(bfr, SIZE);

	sleep(1);


	printf("Reception 1 completed successfully!\n");

	
	unsigned char decryptedtext[SIZE];
	unsigned char decryptedtextlbl[SIZE];

	FILE *file_ignk = fopen("ignition_key_server.txt", "r"); 
	char prekey[17];
	int cnt=0;
	char chr;

    while (chr != EOF){
        chr = fgetc(file_ignk);
		prekey[cnt]=chr;
		cnt++;
    } 
 
	prekey[16] = '\0';
    fclose(file_ignk);


	unsigned char *key = (unsigned char *)prekey;

	unsigned char *iv = (unsigned char *) init_vec;


	unsigned char *ciphertext_pointer = (unsigned char *)ciphertext_dec;

	unsigned char *ciphertext_pointerlbl = (unsigned char *)ciphertextlbl_dec;

	decrypt(ciphertext_pointer, ciphertext_lenchall, key, iv, decryptedtext);
	


	decrypt(ciphertext_pointerlbl, ciphertextlbl_len, key, iv, decryptedtextlbl);
	


	unsigned char* chall_dec = remove_padd(decryptedtext);
	unsigned char* label_dec = remove_padd(decryptedtextlbl);


	printf("Decryption of the message from the client successfully completed!\n");


	time_t t1;
	srand ( (unsigned) time (&t1));


	char init_vec_srv[17];
    for (int i = 0; i < 16; i++) {
        init_vec_srv[i] = '0' + rand() % 10;
    }
	init_vec_srv[16] = '\0';
	unsigned char *ivsrv = (unsigned char *) init_vec_srv;


	unsigned char *plaintextlbl = (unsigned char *)label_dec; 
	unsigned char ciphertextlbl[SIZE];
	int ciphertext_lenlbl;
	ciphertext_lenlbl = encrypt(plaintextlbl, strlen ((char *)plaintextlbl), key, ivsrv, ciphertextlbl);


	unsigned char *plaintext = (unsigned char *)chall_dec;
	unsigned char ciphertext[SIZE];
	int ciphertext_len;
	ciphertext_len = encrypt(plaintext, strlen ((char *)plaintext), key, ivsrv, ciphertext);



	FILE *file_nk = fopen("network_key.txt", "r"); 
	char netkey[17];
	int cntnk=0;
	char chrnk;

    while (chrnk != EOF){
        chrnk = fgetc(file_nk);
		netkey[cntnk]=chrnk;
		cntnk++;
    } 
 
	netkey[16] = '\0';
    fclose(file_nk);


	unsigned char *plaintextnk = (unsigned char *)netkey;
	unsigned char ciphertextnk[SIZE];
	int ciphertext_lennk;
	ciphertext_lennk = encrypt(plaintextnk, strlen ((char *)plaintextnk), key, ivsrv, ciphertextnk);



	FILE *file_dk = fopen("device_key.txt", "r"); 
	char dkey[17];
	int cntdk=0;
	char chrdk;

    while (chrdk != EOF){
        chrdk = fgetc(file_dk);
		dkey[cntdk]=chrdk;
		cntdk++;
    } 
 
	dkey[16] = '\0';
    fclose(file_dk);




	FILE *file_IED = fopen("IED.txt", "r"); 
	char IED[9];
	int cntIED=0;
	char chrIED;

    while (chrIED != EOF){
        chrIED = fgetc(file_IED);
		IED[cntIED] = chrIED;
		cntIED++;
    } 
	IED[8] = '\0';
    fclose(file_IED);

	if( strcmp((char *)label_dec, IED )== 0 ){
		printf("IED label: %s!!!\n", IED);
		printf("Correct IED label!!!\n");
	}
	else{
		printf("IED label: %s!!!\n", IED);
		printf("Wrong IED label!!!\n");
		exit(1);
	}



	unsigned char *plaintextdk = (unsigned char *)dkey;
	unsigned char ciphertextdk[SIZE];
	int ciphertext_lendk;
	ciphertext_lendk = encrypt(plaintextdk, strlen ((char *)plaintextdk), key, ivsrv, ciphertextdk);


	char pom11[10];
	sprintf(pom11, "%d", ciphertext_lenlbl);

	char pom12[10];
	sprintf(pom12, "%d",ciphertext_len);

	char pom13[10];
	sprintf(pom13, "%d",ciphertext_lennk);

	char pom14[10];
	sprintf(pom14, "%d",ciphertext_lendk);


	sleep(1);
	if (send(socket_commu, ciphertextlbl, sizeof(ciphertextlbl), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);
	if (send(socket_commu, ciphertext, sizeof(ciphertext), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);
	if (send(socket_commu, ciphertextnk, sizeof(ciphertextnk), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);
	if (send(socket_commu, ciphertextdk, sizeof(ciphertextdk), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);
	if (send(socket_commu, init_vec_srv, sizeof(init_vec_srv), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);
	if (send(socket_commu, pom11, sizeof(pom11), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);
	if (send(socket_commu, pom12, sizeof(pom12), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);
	if (send(socket_commu, pom13, sizeof(pom13), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);
	if (send(socket_commu, pom14, sizeof(pom14), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);


	printf("Sending successfully completed!\n");

	

	sleep(2);



	sleep(1);
	unsigned char ctchallenge[SIZE];
	if (recv(socket_commu, ctchallenge, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}

	sleep(1);
	char ivesrv[30];
	if (recv(socket_commu, ivesrv, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}


	char bfr2[SIZE];

	sleep(1);
	int chlen;
	if (recv(socket_commu, bfr2, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}
	chlen = atoi(bfr2);
	bzero(bfr2, SIZE);
	sleep(1);


	printf("Reception 2 completed successfully!!\n");


	unsigned char *keynk = (unsigned char *)netkey;
	unsigned char *initializationvector = (unsigned char *) ivesrv;


	unsigned char dtchl[SIZE];
	unsigned char *ptchl = (unsigned char *)ctchallenge;
	decrypt(ptchl, chlen, keynk, initializationvector, dtchl);
	unsigned char* chldec = remove_padd(dtchl);

	printf("Decryption of the message from the client successfully completed!\n");

	if(strcmp((char *)chldec, (char *)chall_dec)==0 ){
		printf("The received challenge matches the one received at the beginning!\n");
	}
	else{
		printf("The received challenge does not match the one received at the beginning!\n");
		exit(1);
	}


	printf("Protocol successfully completed!!\n");



	close(socketfiledesc);
}
