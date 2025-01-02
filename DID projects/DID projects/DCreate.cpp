#include "DCreate.h"
#include <openssl/applink.c>
//sm2(seed)->pk,sk 
//sm3(pk)->DID (hash way)

//Errors deal

static std::string pkStr = "";


void handleErrors() {
    // print errors to stderr;
    ERR_print_errors_fp(stderr);
    // break;
    abort();
}

void saveKeyToPEM(EVP_PKEY* pkey, const char* filename) {
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        std::cerr << "Unable to open file for writing!" << std::endl;
        return;
    }
    if(filename == "sm2_private.pem"){
        if (PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 0) {
            handleErrors();
        }
    }
    else if(filename == "sm2_public.pem") {
        if (PEM_write_PUBKEY(fp, pkey)==0) {
            handleErrors();
        }
    }

    fclose(fp);
}

std::string publicKeyToString(EVP_PKEY* pKey) {

    BIO* bio = BIO_new(BIO_s_mem());

    //read pub_key from pKey and store it in bio
    if (PEM_write_bio_PUBKEY(bio, pKey) != 1) {
        handleErrors();
    }

    // get the pub_key length
    size_t pubKeyLen = BIO_pending(bio);
    std::string pubKey(pubKeyLen, '\0'); // use pubKey to store pub_key

    // read pub_key from bio to pubKey 
    BIO_read(bio, &pubKey[0], pubKeyLen);
    BIO_free(bio); // free bio

    return pubKey; // return pubKey
}

// Hex to String
std::string hexToString(const unsigned char* hash, unsigned int length) {
    std::stringstream ss;
    for (unsigned int i = 0; i < length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

bool StringWithHash(std::string *pubKeyStr, unsigned char* buffer, unsigned int* buf_len) {
    //store pubKeys
    std::vector<std::string> inputs;

    //Dereference here
    inputs.push_back(*pubKeyStr);
    
    //Initialize buffer
    memset(buffer, 0, *buf_len);
    //Initialize hash context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // use SM3
    if (!EVP_DigestInit_ex(ctx, EVP_sm3(), NULL)) {
        std::cout << "Failed to init" << std::endl;
        return false;
    }

    for (const auto& i : inputs) {
        if (!EVP_DigestUpdate(ctx, i.c_str(), i.size())) {
            std::cout << "Failed to update" << std::endl;
            return false;
        }
    }

    if (!EVP_DigestFinal_ex(ctx, buffer, buf_len)) {
        std::cout << "Failed to final" << std::endl;
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}

std::string dealWithPks(std::string pubKeyStr) {
    std::istringstream iss(pubKeyStr);
    std::string line;
    std::getline(iss, line);
    while (std::getline(iss, line)) {
        if (line != "-----END PUBLIC KEY-----") {
            pkStr += line;
        }
    }

   // std::cout << pkStr<<std::endl;
    return pkStr;
}

std::string Gen_DID() {
    const char* filename = "sm2_public.pem";
    //open file and get public key
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        std::cerr << "Unable to open file!" << std::endl;
        return "fail";
    }


    EVP_PKEY* pKey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    if (!pKey) {
        handleErrors();
    }

    std::string pubKeyStr = publicKeyToString(pKey);//the pks there is like this ,u should deal with it
    /*-----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEY72JWQoZ88wDlSKqJjUlJNUNPCDj
      XdY74nr2xWBzpBg8AkPZSwhTdL0080GBhbxAeGeJK+Ps4IH2vvoCzHkBVQ==
      -----END PUBLIC KEY-----*/

    pkStr = dealWithPks(pubKeyStr);

    std::cout << "Public Key:\n" << pkStr << std::endl;

    // clean
    EVP_PKEY_free(pKey);
    fclose(fp);

    //-------------------------
    //Hash-sm3

    unsigned char buffer[SM3_DIGEST_LENGTH]; 
    unsigned int buffer_len = sizeof(buffer);
    StringWithHash(&pubKeyStr,buffer,&buffer_len);//Array names are implicitly converted to pointers here so dont need *buffer
    std::string did_identifier = hexToString(buffer, buffer_len);


    std::cout << "-------------------------" << std::endl;
    std::cout << "did_identifier:" << std::endl;
    std::cout << did_identifier << std::endl;
    return did_identifier;

    
}

std::string did_create() {
    // ³õÊ¼»¯ OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, nullptr);
    if (!ctx) handleErrors();
    //generate sk
    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();
    //generate pk pairs
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handleErrors();

    BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    // print public_key
    std::cout << "Public Key:" << std::endl;
    if (EVP_PKEY_print_public(bio, pkey, 4, nullptr) <= 0) {
        handleErrors();
    }
    //-----------------------------------------------------
    // print private_key, it should be hidded!!!
    std::cout << "Private Key:" << std::endl;
    if (EVP_PKEY_print_private(bio, pkey, 4, nullptr) <= 0) {
        handleErrors();
    }
    //-----------------------------------------------------


    // print parameters
    std::cout << "\nParameters:" << std::endl;
    if (EVP_PKEY_print_params(bio, pkey, 4, nullptr) <= 0) {
        handleErrors();
    }

    saveKeyToPEM(pkey, "sm2_private.pem");
    saveKeyToPEM(pkey, "sm2_public.pem");


    // clean
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    EVP_cleanup();
    ERR_free_strings();

    std::cout << "SM2 private key generates successfully!" << std::endl;
    // do not use the pk or sk above ,but use the .pem file is better 

    std::string did_identifier = Gen_DID();

    


    //-----------------------------------------------------
    std::cout << "-----------------------------------------------------" << std::endl;
    std::string did = "did:key:" + did_identifier;
    std::cout << "DID:" <<std::endl;
    std::cout <<did<< std::endl;

    std::cout << "------------------------------------------------------" << std::endl;
    std::cout << "DID Document:" << std::endl;
    if (DidDoc_Create(pkStr, did_identifier)) {
    std::cout << "DID Document makes successful!" << std::endl;
    }


    return did;
}



