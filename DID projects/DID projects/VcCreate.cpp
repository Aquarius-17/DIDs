#include "VcCreate.h"
#include "DCreate.h"

Json::Value Graph_Init(std::string &type, std::string &question ,std::string &answer,std::string &issuer,std::string &id) {
    Json::Value graph;

    //root property
    graph["@context"] = Json::Value("https://www.w3.org/ns/did/v1");
    // root["@context"].append("");
    graph["type"] = Json::Value(type);

    std::time_t nowTime = std::time(nullptr);
   // std::cout << "当前时间 (使用 ctime): " << std::ctime(&nowTime);

    graph["issuanceDate"] = Json::Value(std::ctime(&nowTime));
    graph["issuer"] = Json::Value(issuer);
    Json::Value credentialSubject = CredentialSubject_Init(id,question,answer);
    graph["credentialSubject"] = Json::Value(credentialSubject);
    return graph;

}

//the answer here can be change into Json::Value, then u can add more details here
Json::Value CredentialSubject_Init(std::string id, std::string question, std::string answer) {
    Json::Value credentialSubject;
    credentialSubject["id"] = Json::Value(id);
    credentialSubject[question] = Json::Value(answer);
    return credentialSubject;
}


//base64_encode method to string;
std::string base64_encode(const unsigned char* buffer, size_t length) {
    BIO* bio;
    BIO* b64;
    BUF_MEM* bufferPtr;

    // gen base64 bio and bio;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // 不添加换行符

    // write buffer here
    BIO_write(b64, buffer, length);
    BIO_flush(b64);

    // gen string
    BIO_get_mem_ptr(b64, &bufferPtr);
    BIO_set_close(b64, BIO_NOCLOSE);
    BIO_free_all(b64);

    return std::string(bufferPtr->data, bufferPtr->length);
}
//base64 decode
std::string base64_decode(const std::string& base64) {
    BIO* bio;
    BIO* b64;
    char buffer[512];  // decode buffer
    int length;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(base64.data(), base64.length());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  

    // read datas
    length = BIO_read(b64, buffer, base64.length());
    BIO_free_all(b64);

    return std::string(buffer, length);  // return strings
}

std::string Jws_Gen(Json::Value graph) {
    
    //generate rsa keys;

    RSA* rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, 2048, nullptr, nullptr) !=1) {
        handleErrors();
    }

    BIO* bio_pub = BIO_new(BIO_s_mem());
    BIO* bio_priv = BIO_new(BIO_s_mem());

    PEM_write_bio_RSA_PUBKEY(bio_pub, rsa);

    PEM_write_bio_RSAPrivateKey(bio_priv, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    //get public_key and private_key;
    
    BUF_MEM* buf_pub;
    BIO_get_mem_ptr(bio_pub, &buf_pub);
    std::string public_key(buf_pub->data, buf_pub->length);

    BUF_MEM* buf_priv;
    BIO_get_mem_ptr(bio_priv, &buf_priv);
    std::string private_key(buf_priv->data, buf_priv->length);

    //make graph into strings;

    Json::StreamWriterBuilder writers;

    std::string message = Json::writeString(writers, graph);

    //calculate the hash of the message ,then use the hash to sign;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message.c_str(), message.length(), hash);

    unsigned char signature[4098] = {};
    unsigned int signature_length;
    //sign method
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &signature_length, rsa) != 1) {
        handleErrors();
    }

    std::cout << "Signature generated successfully." << std::endl;

   
    //verify method;
    if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, signature_length, rsa) != 1) {
        std::cout << "Signature verification failed." << std::endl;
    }
    else {
        std::cout << "Signature verification succeeded." << std::endl;
    }

     std::string jws = base64_encode(signature, signature_length);


    // clean up
    BIO_free_all(bio_pub);
    BIO_free_all(bio_priv);
    RSA_free(rsa);

    return jws;
}

//when u want to verify ,u need to make the jws into base64_decode (signature),
// use the hash_graph ,read the key from did_doc use the verify way to verify it;

Json::Value Proof_Init(std::string type, std::string proofPurpose, std::string verificationMethod, Json::Value& graph) {
    Json::Value proof;
    proof["type"] = Json::Value(type);
    std::time_t nowTime = std::time(nullptr);
    proof["created"] = Json::Value(std::ctime(&nowTime));
    proof["proofPurpose"] = Json::Value(proofPurpose);
    proof["verificationMethod"] = Json::Value(verificationMethod);

    std::string jws = Jws_Gen(graph);
    proof["jws"] = Json::Value(jws);

    return proof;

}

bool Vc_Create(std::string type, std::string question, std::string answer, std::string issuer, std::string id, std::string proofPurpose, std::string verificationMethod) {
    Json::Value graph = Graph_Init(type, question, answer, issuer, id);
    Json::Value proof = Proof_Init(type, proofPurpose, verificationMethod, graph);
    graph["proof"] = Json::Value(proof);
    Json::StyledWriter sw;
    std::cout << sw.write(graph) << std::endl;
    return true;
}