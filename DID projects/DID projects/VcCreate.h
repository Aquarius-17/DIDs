#pragma once
#pragma warning(disable:4996)


#include <string>
#include <json.h>
#include <ctime>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

bool Vc_Create(std::string type, std::string question, std::string answer, std::string issuer, std::string id, std::string proofPurpose, std::string verificationMethod);
Json::Value Graph_Init(std::string& type, std::string& question, std::string& answer, std::string& issuer, std::string& id);
Json::Value CredentialSubject_Init(std::string id, std::string question, std::string answer);
Json::Value Proof_Init(std::string type, std::string proofPurpose, std::string verificationMethod, Json::Value& graph);
std::string base64_encode(const unsigned char* buffer, size_t length);
std::string base64_decode(const std::string& base64);
std::string Jws_Gen(Json::Value graph);