#ifndef BB_CONFIG_T_H
#define BB_CONFIG_T_H

#define APP_PARAMETER_DATA_TYPE uint8_t
#define PARAM_T APP_PARAMETER_DATA_TYPE
#define APP_NUM_OF_PARAMETERS_SIZE_BYTES 4
#define MAX_EMAIL_SIZE_BYTES 35
#define MIN_EMAIL_SIZE_BYTES 6

typedef struct _bb_config_t {
    uint32_t num_of_neighbors;
    uint32_t num_of_vertices;
    char    email[MAX_EMAIL_SIZE_BYTES];
    PARAM_T params[APP_NUM_OF_PARAMETERS_SIZE_BYTES];
    //PARAM_T neighbor_params[][APP_NUM_OF_PARAMETERS_SIZE_BYTES];
} bb_config_t;

#endif