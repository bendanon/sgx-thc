#include "../BlackBoxExecuter.h"
#include <gtest/gtest.h>
#include <iostream>

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


#define MSG_SIZE (THC_ENCRYPTED_MSG_SIZE_BYTES(NUM_OF_BBX))
#define MSG(bufPtr, msgNumber) (bufPtr + ((msgNumber)%2)*MSG_SIZE)
#define EMAIL "bendanon@gmail.com"

TEST(bbxTest, FullMesh_10){

	int NUM_OF_BBX = 10;
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

	uint8_t secret[SECRET_KEY_SIZE_BYTES];
	sgx_read_rand(secret, SECRET_KEY_SIZE_BYTES);

	bb_config_t config;
	config.num_of_vertices = NUM_OF_BBX;
	memcpy(config.email,EMAIL,sizeof(EMAIL));
	sgx_read_rand(config.params, APP_NUM_OF_PARAMETERS);

	for (int i = 0; i < NUM_OF_BBX; i++){
		config.num_of_neighbors = numTargets[i];
		ASSERT_TRUE(bbx[i].Initialize(&config));
		ASSERT_TRUE(bbx[i].SetSecret(secret, SECRET_KEY_SIZE_BYTES));
	}

   uint8_t bbxMsg[NUM_OF_BBX][MSG_SIZE*2];
   uint8_t* ptr[NUM_OF_BBX];

    for (int i = 0; i < NUM_OF_BBX; i++){
        ptr[i] = bbxMsg[i];        
        ASSERT_TRUE(bbx[i].GenerateFirstMessage(MSG(ptr[i], 0), MSG_SIZE));
    }

	/*Graph collection phash*/
	for(int i = 0; i < NUM_OF_BBX; i++){
		for(int j = 0; j < NUM_OF_BBX; j++){
			for(int k = 0; k < numTargets[j]; k++){
				ASSERT_TRUE(bbx[j].Execute(MSG(ptr[source[j][k]], i), MSG_SIZE, MSG(ptr[j], i+1), MSG_SIZE));
			}
		}
	}

	//After graph collection, all bbx's should contain the same graph
	for(int j = 1; j < NUM_OF_BBX; j++){
		ASSERT_TRUE(bbx[j].CompareGraph(bbx[j-1]));
	}

	/*Consistency checking phash*/
	for(int i = 0; i < NUM_OF_BBX*NUM_OF_BBX; i++){
		for(int j = 0; j < NUM_OF_BBX; j++){
			for(int k = 0; k < numTargets[j]; k++){
				ASSERT_TRUE(bbx[j].Execute(MSG(ptr[source[j][k]], i), MSG_SIZE, MSG(ptr[j], i+1), MSG_SIZE));
			}
		}
	}
	
	const char desired_result[] = "RESULT," EMAIL ", " EMAIL;
	for(int j = 0; j < NUM_OF_BBX; j++){
		ASSERT_EQ(0, memcmp(desired_result, MSG(ptr[j], (NUM_OF_BBX*NUM_OF_BBX)), strlen(desired_result)));
	}
}

int main(int argc, char **argv){
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
