#include "Header.h"

int main() {

	std::cout << "Generate rA,rB and identifiers\n";
	std::string serverR,serverID, clientR,clientID;
	std::string key = Key();
	std::string concClient,concServer,HBI_1,HAI_1,HAI_2,HBI_2;
	serverR = generateR(serverR);
	clientR = generateR(clientR);
	serverID = generateID(serverID);
	clientID = generateID(clientID);
	std::cout << "Result\n1.Client : rA : " << clientR << " ID : " << clientID
		<< "\n2.Server : rB : " << serverR << "  ID : " << serverID;

	//client first iteration
	std::cout << "\nClient getting rB from Server.......\n";
	std::cout << "\nConcatenation rA,rB and iB on client side";
	concClient = Concatenation({ clientR, serverR, serverID });
	std::cout << "\nResult : " << concClient;
	std::cout << "\nHashing data......";
	HBI_1 = HMAC_SHA3_256(concClient, key);
	std::cout << "\nHash : " << HBI_1;

	//server first iteration
	std::cout << "\nServer getting hBI from client.......\n";
	std::cout << "\nConcatenation rA,rB and iA on Server side";
	concServer = Concatenation({ clientR,serverR,clientID });
	std::cout << "\nResult : " << concServer;
	std::cout << "\nHashing data......";
	HAI_1 = HMAC_SHA3_256(concServer, key);
	std::cout << "\nHash : " << HAI_1;

	//client second iteration
	std::cout << "\nClient getting hAI from client.......\n";
	std::cout << "\nConcatenation rA,rB and iA on client side";
	concClient = Concatenation({ clientR, serverR, clientID });
	std::cout << "\nResult : " << concClient;
	std::cout << "\nHashing data......";
	HAI_2 = HMAC_SHA3_256(concClient, key);
	std::cout << "\nHash : " << HAI_2;

	//server second iteration
	std::cout << "\nServer getting hBI from client.......\n";
	std::cout << "\nConcatenation rA,rB and iB on server side";
	concServer = Concatenation({ clientR, serverR, serverID });
	std::cout << "\nResult : " << concServer;
	std::cout << "\nHashing data......";
	HBI_2 = HMAC_SHA3_256(concServer, key);
	std::cout << "\nHash : " << HBI_2;


	////authorization
	//HAI_1 = "asdasd";
	std::cout << "\nAuthorization on both sides......";
	if (HAI_1 == HAI_2 && HBI_1 == HBI_2) 
		std::cout << "\nAuthorization SUCCESSFUL!\n\n\n";
	else
		std::cout << "\nAuthorization FAILED!\n\n\n";
		
	
	return 0;
}