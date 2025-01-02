
#pragma once
#ifndef DID_CREATE_H

#define DID_CREATE_H
#include <iomanip>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/encoder.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include "DDCreate.h"


#define SM3_DIGEST_LENGTH 32

void handleErrors();
void saveKeyToPEM(EVP_PKEY* pkey, const char* filename);
std::string publicKeyToString(EVP_PKEY* pKey);
std::string hexToString(const unsigned char* hash, unsigned int length);
bool StringWithHash(std::string* pubKeyStr, unsigned char* buffer, unsigned int* buf_len);
std::string dealWithPks(std::string pubKeyStr);
std::string Gen_DID();
std::string did_create();


#endif // !DID_CREATE.H
