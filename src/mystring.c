#include "../include/mystring.h"

boolean IsAddress(char *inputString){
    return False;
}

char *GetInfoFromStr(char *inputString, int option){
    char *result;
    size_t strLength = strlen(inputString);
    result = (char *) malloc(strLength * sizeof(char));

    if(option == NETWORK_ADDR)
    {
        for (size_t i = 0; i <= strLength; i = i + 1)
        {
            if(i == strLength || inputString[i] == '/')
            {
                result[i] = '\0';
                break;
            }
            result[i] = inputString[i];
        }
    }
    else if(option == SUBNET_MASK)
    {
        size_t j = 0;
        for (size_t i = 0; i <= strLength; i = i + 1)
        {
            if(inputString[i] == '/')
            {
                j = i + 1;
                break;
            }          
        }
        for (size_t i = 0; i <= strLength; i = i + 1)
        {
            if(j == strLength)
            {
                result[j] = '\0';
                break;
            }          
            result[i] = inputString[j];
            j = j + 1;
        }
    }
    return result;
}

void FreeString(char * stringToFree){
    if(stringToFree != NULL)
    {
        free(stringToFree);
    }
}