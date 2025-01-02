#include "DDCreate.h"


bool DidDoc_Create(std::string pubkey,std::string didstr) {
	
	//get the publickey from input ,use a template to make did-document

    Json::Value root=DidDoc_Init(didstr, pubkey);

    std::cout << "StyledWriter:" << std::endl;
    Json::StyledWriter sw;
    std::cout << sw.write(root) << std::endl;

    std::string filePath = didstr + ".json"; // file path
    try {
        std::ofstream os(filePath, std::ios::out | std::ios::app); // open file with append way
        if (!os) {
            throw std::runtime_error("Cannot open file: " + filePath);
        }
        os << sw.write(root);
        return true;
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return false;
    }

    




}
Json::Value DidDoc_Init(std::string& didstr, std::string& pubkey)
{
    //root node

    Json::Value root;

    //root property
    root["@context"] = Json::Value("https://www.w3.org/ns/did/v1");
    // root["@context"].append("");
    root["id"] = Json::Value(didstr);
    //root["authentication"] = Json::Value("");
    //root["capabilityInvocation"] = Json::Value("");
    //root["assertionMethod"] = Json::Value("");

    //add child node
    Json::Value verificationMethod;
    verificationMethod["id"] = Json::Value(didstr + "#key-0");
    verificationMethod["type"] = Json::Value("SM2 Key Pairs");
    verificationMethod["controller"] = Json::Value(didstr);
    verificationMethod["publicKeyMultibase"] = Json::Value(pubkey);
    //add child node to root
    root["verificationMethod"] = Json::Value(verificationMethod);

    return  root;

}
//DID Example1 for basic info
/*
  {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "did:example:123",
    "authentication": [
      {
        "id": "did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3",
        "type": "Ed25519VerificationKey2020", // external (property value)
        "controller": "did:example:123",
        "publicKeyMultibase": "zAKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf"
      }
    ],
    "capabilityInvocation": [
      {
        "id": "did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k",
        "type": "Ed25519VerificationKey2020", // external (property value)
        "controller": "did:example:123",
        "publicKeyMultibase": "z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN"
      }
    ],
    "capabilityDelegation": [
      {
        "id": "did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi",
        "type": "Ed25519VerificationKey2020", // external (property value)
        "controller": "did:example:123",
        "publicKeyMultibase": "zHgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL"
      }
    ],
    "assertionMethod": [
      {
        "id": "did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY",
        "type": "Ed25519VerificationKey2020", // external (property value)
        "controller": "did:example:123",
        "publicKeyMultibase": "z5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA"
      }
    ]
}

*/

//DID Example2 -- for keys management -- all keys are in the Verififcation Method

//Q1: How to judge how many keys now we have? -- at the beginning ,we dont need to care about it ,because
//    now we only need to use the pubKey to verify the identity .so only one key here at first.

/*
"verificationMethod": [
{
    "id": "did:example:123#key-0",
        "type" : "JsonWebKey2020",
        "controller" : "did:example:123",
        "publicKeyJwk" : {
        "kty": "OKP", // external (property name)
            "crv" : "Ed25519", // external (property name)
            "x" : "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ" // external (property name)
    }
  }
]
*/


//DID Example3 -- for Verification Methods management -- all in the Verification Method
/*"verificationMethod": [
    {
      "id": "did:example:123#key-0",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:example:123",
      "publicKeyBase58": "3M5RCDjPTWPkKSN3sxUmmMqHbmRPegYP1tjcKyrDbt9J" // external (property name)
    }
 ]
 */

