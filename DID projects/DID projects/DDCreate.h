#pragma once
# include<json.h>
#include <string>
#include <iostream>
#include <fstream>

extern std::string pkStr;

bool DidDoc_Create(std::string pubkey, std::string didstr);

Json::Value DidDoc_Init(std::string& didstr, std::string& pubkey);
