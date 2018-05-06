
#include "../BbApplication/bb_enclave/BlackBoxExecuter.h"
#include <iostream>

//typedef unsigned int sgx_status_t;

//#define SGX_AESGCM_KEY_SIZE 32
//#define SGX_SUCCESS 0

sgx_status_t sgx_read_rand(unsigned char *randbuf, size_t length_in_bytes){

    for(int i = 0; i < length_in_bytes; i++){
        randbuf[i] = rand();
    }
    return SGX_SUCCESS;

}

sgx_status_t encrypt(uint8_t* plaintext, size_t plaintext_size,  
                         uint8_t* ciphertext, uint8_t key[SGX_AESGCM_KEY_SIZE]){
                            memcpy(ciphertext, plaintext, plaintext_size);
                            return SGX_SUCCESS;
                         }

sgx_status_t decrypt(uint8_t* plaintext, size_t plaintext_size,
                         uint8_t* ciphertext, uint8_t key[SGX_AESGCM_KEY_SIZE]){
                             memcpy(plaintext, ciphertext, plaintext_size);
                             return SGX_SUCCESS;
                         }

void ocall_print(const char* format, uint32_t number){
    char output[500];
    memset(output,0,500);
    snprintf(output, 500, format, number);
    std::cout << output << "\n";
}

void ocall_print(const char* format){
    std::cout << format << "\n";
}

void print_buffer(uint8_t* buffer, size_t len){
    char toPrint[len * 3 + 3];
    char* ptr = toPrint;

    snprintf(ptr++,2, "[");

    for(int i = 0; i < len; i++){
        snprintf(ptr, 4, "%02X,", (unsigned char)buffer[i]);
        ptr = ptr + 3;
    }
    
    snprintf(ptr-1, 3, "]");

    ocall_print(toPrint);
}


#define NUM_OF_BBX (30)
#define MSG_SIZE (THC_ENCRYPTED_MSG_SIZE_BYTES(NUM_OF_BBX))
#define MSG(bufPtr, msgNumber) (bufPtr + ((msgNumber)%2)*MSG_SIZE)
#define EMAIL "bendanon@gmail.com"


int main() {
    
    printf("MAX_EDGES is %d\n", MAX_EDGES(NUM_OF_BBX));

    BlackBoxExecuter bbx[NUM_OF_BBX];	
	uint32_t source[NUM_OF_BBX][NUM_OF_BBX-1];
	uint32_t numTargets[NUM_OF_BBX]; //= {1,3,2,1,2,2};
		
	for (int i = 0; i < NUM_OF_BBX; i++){
	    numTargets[i] = NUM_OF_BBX - 1;
	    for (int j = 0; j < NUM_OF_BBX - 1; j++){
	        if(j < i) source[i][j] = j;
	        else source[i][j] = j+1;
	    }
	}
    
/*for (int i = MAX_NEIGHBORS(NUM_OF_BBX); i < NUM_OF_BBX-1; i++){
        source[i][0] = i+1;
    }*/

    /*source[0][0] = 1;

    source[1][0] = 0;
    source[1][1] = 2;
    source[1][2] = 4;

    source[2][0] = 1;
    source[2][1] = 3;

    source[3][0] = 2;

    source[4][0] = 1;
    source[4][1] = 5;

    source[5][0] = 4;
    source[5][1] = 3;*/

    uint8_t secret[SECRET_KEY_SIZE_BYTES];
    sgx_read_rand(secret, SECRET_KEY_SIZE_BYTES);

   bb_config_t config;
   config.num_of_vertices = NUM_OF_BBX;
   memcpy(config.email,EMAIL,sizeof(EMAIL));
   sgx_read_rand(config.params, APP_NUM_OF_PARAMETERS);

   for (int i = 0; i < NUM_OF_BBX; i++){

        config.num_of_neighbors = numTargets[i];

        if(!bbx[i].Initialize(&config)){
            printf("Failed to initialize bbx[%d]\n", i);
            return 1;
        }

       if(!bbx[i].SetSecret(secret, SECRET_KEY_SIZE_BYTES)){
           printf("Failed to set bbx secret\n");
           return 1;
       }
   }

   uint8_t bbxMsg[NUM_OF_BBX][MSG_SIZE*2];
   uint8_t* ptr[NUM_OF_BBX];

    for (int i = 0; i < NUM_OF_BBX; i++){
        ptr[i] = bbxMsg[i];
        
        if(!bbx[i].GenerateFirstMessage(MSG(ptr[i], 0), MSG_SIZE)){
            printf("Failed to GenerateFirstMessage\n");
            return 1;
        }
    }

   bool fDone = false;
   for(int i = 0; true; i++){

        for(int j = 0; j < NUM_OF_BBX; j++){
            for(int k = 0; k < numTargets[j]; k++){

                //printf("======bbx[%d], before message %d, source is %d:=========\n", j, i+1, source[j][k]);
                //bbx[j].Print();
                if(!bbx[j].Execute(MSG(ptr[source[j][k]], i), MSG_SIZE, MSG(ptr[j], i+1), MSG_SIZE)){
                    printf("bbx[0].Execute failed\n");
                    return -1;
                }
                //printf("======bbx[%d], after message %d:=========\n", j, i+1);
                //bbx[j].Print();
                //getchar();
            }
        }

        for(int j = 0; j < NUM_OF_BBX; j++){

            if(0==memcmp(ABORT_MESSAGE, MSG(ptr[j], i+1), strlen(ABORT_MESSAGE))){
                printf("abort recieved from %d: %s\n", j, MSG(ptr[j], i+1));
                fDone = true;               
            } else if(0==memcmp(RESULT_CANARY, MSG(ptr[j], i+1), strlen(RESULT_CANARY))){
               printf("result recieved from %d: %s\n", j, MSG(ptr[j], i+1));
               fDone = true;               
            }
        }
       
       printf("round %d\n", i);

        if(fDone){

            for(int j = 1; j < NUM_OF_BBX; j++){
                if(bbx[j].CompareGraph(bbx[j-1])){
                    printf("========bbx[%d] and bbx[%d] have equivalent graphs:=========\n", j, j-1);    
                }
                else{
                    for(int i = 1 ; i < 10 ; i++) printf("================\n");
                    bbx[j-1].Print();
                    for(int i = 1 ; i < 5 ; i++) printf("================\n");
                    bbx[j].Print();                    
                }
            }

            for(int j = 0; j < 1; j++){
                printf("========bbx[%d]'s final state is:=========\n", j);
                bbx[j].Print();
            }
            return 0;
        }
   }
 
   return 0;
}