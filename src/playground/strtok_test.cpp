#include <stdio.h>
#include <string.h>
#include <string>

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i ==4) {
            for (i=0; i<4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i=0; i<3; i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j=i; j<4; j++)
            char_array_4[j] = 0;

        for (j=0; j<4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j=0; j<i-1; j++) 
			ret += char_array_3[j];
    }

    return ret;
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i=0; i<4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j=0; j<i+1; j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::string extractQuoteBody(char* report_buf){
    char *tok = strstr(report_buf, "isvEnclaveQuoteBody");
    int counter = 0;
    while ((tok = strtok(tok, "\"")) != NULL)
    {
        if(2 == counter) {
            std::string quoteBody(tok);
            return quoteBody;
        }        
        tok = NULL;
        counter++;
    }
    return "";
}

int main(void)
{
    char report_buf[] = "{\"id\":\"24020265441822544410902250018689140812\",\"timestamp\":\"2018-04-01T11:48:46.249500\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000500000707020401010000000000000000000005000006000000020000000000000AC8856CC575291620BBF11595D4E7BE33DF16E1EC33E6CDF8003237A542E81E0F59F4D842078CB094379848FEE8F95635F70E45814892B67B1E822CEA4B9E40DBC5\",\"isvEnclaveQuoteBody\":\"AgAAAMgKAAAFAAQAAAAAAKx/3QbhJMVkvh5sZm978EtX1LY6EAJ5rAUkvHHbRDbkBQX///8CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAANde5vd5nSKeXadVk8cHoAkrA24WOfKhh13Gyxeaeh63AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACKA+BoUMOqSjV+3vfGJB0iCAKGMgR5dC4PBgAOM/udlgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADsQReVb3Zxpy+nZ+hGuoOSnN5juKjhsTWWAv9gAS8HtwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
    std::string body = extractQuoteBody(report_buf);
    printf("body: %s\n", body.c_str());
    
    return 0;
}