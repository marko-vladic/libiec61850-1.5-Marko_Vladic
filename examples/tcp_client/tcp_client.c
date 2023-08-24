#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
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

	FILE *file = fopen("ignition_key.txt", "r"); 

	time_t t1;
	char chr;



	char prekey[17];
	int cnt=0;

    while (chr != EOF){
        chr = fgetc(file);
		prekey[cnt]=chr;
		cnt++;
    } 
 
	prekey[16] = '\0';         
    fclose(file);




	srand ( (unsigned) time (&t1));

	int upper = 999999999;
	int lower = 1000000;
	int rand_numb = (rand() % (upper - lower + 1)) + lower;

	char challenge[11];
	sprintf(challenge,"%d", rand_numb);


	char init_vec[17];

    for (int i = 0; i < 16; i++) {
        init_vec[i] = '0' + rand() % 10;
    }
	init_vec[16] = '\0';                              


	unsigned char *key = (unsigned char *)prekey;
	unsigned char *iv = (unsigned char *) init_vec;
	unsigned char *plaintext = (unsigned char *)challenge;
	unsigned char ciphertext[SIZE];
	int ciphertext_len;
	ciphertext_len = encrypt(plaintext, strlen ((char *)plaintext), key, iv, ciphertext);



	char IED_label[20];
	strcpy(IED_label, "IED21345");


	unsigned char *plaintextlbl = (unsigned char *)IED_label;
	unsigned char ciphertextlbl[SIZE];
	int ciphertext_lenlbl;
	ciphertext_lenlbl = encrypt(plaintextlbl, strlen ((char *)plaintextlbl), key, iv, ciphertextlbl);



	char pom[10];
	sprintf(pom, "%d", ciphertext_len);

	char pom2[10];
	sprintf(pom2, "%d", ciphertext_lenlbl);

	


	struct sockaddr_in socketAddressServer;


	int socketfiledesc = socket(AF_INET, SOCK_STREAM, 0);
	if( socketfiledesc == -1) {
    	printf("Socket not created");
    	exit(0);
    }


	

	bzero(&socketAddressServer, sizeof(socketAddressServer));

	socketAddressServer.sin_family = AF_INET;
	socketAddressServer.sin_addr.s_addr = inet_addr("127.0.0.1");
	socketAddressServer.sin_port = htons(PORT);

	int cnct = connect(socketfiledesc, (SA*)&socketAddressServer, sizeof(socketAddressServer));
	if( cnct != 0) {
    	printf("Not connected");
    	exit(0);
    }
	sleep(1);
	if (send(socketfiledesc, ciphertextlbl, sizeof(ciphertextlbl), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(1);
	if (send(socketfiledesc, ciphertext, sizeof(ciphertext), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(1);
	if (send(socketfiledesc, init_vec, sizeof(init_vec), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(1);
	if (send(socketfiledesc, pom, sizeof(pom), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(1);
	if (send(socketfiledesc, pom2, sizeof(pom2), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(1);
	

	printf("Sending 1 successfully completed!\n");


	sleep(2);



	sleep(1);
	unsigned char ctlbl_dec[SIZE];
	if (recv(socketfiledesc, ctlbl_dec, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}


	sleep(1);
	unsigned char ctchl_dec[SIZE];
	if (recv(socketfiledesc, ctchl_dec, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}


	sleep(1);
	unsigned char ctnk_dec[SIZE];
	if (recv(socketfiledesc, ctnk_dec, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}


	sleep(1);
	unsigned char ctdk_dec[SIZE];
	if (recv(socketfiledesc, ctdk_dec, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}


	sleep(1);
	char ivecli[30];
	if (recv(socketfiledesc, ivecli, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}


	char bfr[SIZE];

	sleep(1);
	int iedlen;
	if (recv(socketfiledesc, bfr, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}
	iedlen = atoi(bfr);
	bzero(bfr, SIZE);

	sleep(1);
	int chlen;
	if (recv(socketfiledesc, bfr, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}
	chlen = atoi(bfr);
	bzero(bfr, SIZE);

	sleep(1);
	int nklen;
	if (recv(socketfiledesc, bfr, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}
	nklen = atoi(bfr);
	bzero(bfr, SIZE);

	sleep(1);
	int dklen;
	if (recv(socketfiledesc, bfr, SIZE, 0) == -1) {
    		perror("[-]Error in receiving file.");
    		exit(1);
	}
	dklen = atoi(bfr);
	bzero(bfr, SIZE);
	sleep(1);


	printf("Reception completed successfully!!\n");

 

	unsigned char *ivcli = (unsigned char *) ivecli; 


	unsigned char dtlbl[SIZE];
	unsigned char *ptlbl = (unsigned char *)ctlbl_dec;  

	decrypt(ptlbl, iedlen, key, ivcli, dtlbl);
	unsigned char* lbldec = remove_padd(dtlbl);   

	unsigned char dtchl[SIZE];
	unsigned char *ptchl = (unsigned char *)ctchl_dec;
	decrypt(ptchl, chlen, key, ivcli, dtchl);
	unsigned char* chldec = remove_padd(dtchl);    


	unsigned char dtnk[SIZE];
	unsigned char *ptnk = (unsigned char *)ctnk_dec;
	decrypt(ptnk, nklen, key, ivcli, dtnk);
	unsigned char* nkdec = remove_padd(dtnk);


	unsigned char dtdk[SIZE];
	unsigned char *ptdk = (unsigned char *)ctdk_dec;
	decrypt(ptdk, dklen, key, ivcli, dtdk);
	unsigned char* dkdec = remove_padd(dtdk);


	printf("Decryption of the message from the server successfully completed!\n");


	FILE *f_netkey = fopen("network_key.txt", "w"); 
	fputs((char *)nkdec, f_netkey);
	fclose(f_netkey);

	FILE *f_devkey = fopen("device_key.txt", "w"); 
	fputs((char *)dkdec, f_devkey);
	fclose(f_devkey);




	if( strcmp((char *)lbldec, IED_label )==0 && strcmp((char *)chldec, challenge)==0 ){
		printf("The received label and challenge match the sent versions!\n");
	}
	else{
		printf("The received label and challenge does not match the sent versions!\n");
		exit(1);
	}


	sleep(1);


	char initialization_vector[17]; 
    for (int i = 0; i < 16; i++) {
        initialization_vector[i] = '0' + rand() % 10;
    }
	initialization_vector[16] = '\0';


	




	unsigned char *keynk = (unsigned char *)nkdec;  
	unsigned char *initializationvector = (unsigned char *) initialization_vector;

	unsigned char *pltxtchall = (unsigned char *)chldec; 
	unsigned char cphrtxtchall[SIZE];
	int cphrtxtchallen;
	cphrtxtchallen = encrypt(pltxtchall, strlen ((char *)pltxtchall), keynk, initializationvector, cphrtxtchall);

	char pom99[10];
	sprintf(pom99, "%d",cphrtxtchallen);



	sleep(2);
	if (send(socketfiledesc, cphrtxtchall, sizeof(cphrtxtchall), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);
	if (send(socketfiledesc, initialization_vector, sizeof(initialization_vector), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(2);
	if (send(socketfiledesc, pom99, sizeof(pom99), 0) == -1) {
    		perror("[-]Error in sending file.");
    		exit(1);
	}
	sleep(1);


	printf("Sending 2 successfully completed!\n");




	printf("Protocol successfully completed!!\n");


	close(socketfiledesc);
}
