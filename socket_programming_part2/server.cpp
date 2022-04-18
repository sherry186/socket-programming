#include<stdio.h>
#include <stdlib.h>
#include<string.h>	//strlen
#include<sys/socket.h>
#include<arpa/inet.h>	//inet_addr
#include<cstring>
#include <iostream>
#include <unistd.h>
#include <pthread.h>
#include <vector>
#include <string> 
#include <mutex> 

using namespace std;

mutex mtx;

int connection_num = 0;

struct USERLIST {
	string name;
	string ip;
	int port;
	int users_port;
	bool online;
	int balance;
	string pk;
	int socket_desc;
};
vector<USERLIST> userlist; 

struct ARGS {
	sockaddr_in *client;
	int sock_desc;
};

void *connection_handler(void *);

void registerNewUser(string username, sockaddr_in *client, int sock_desc);

void login(string loginUser, string port, int sock_desc, string &curUser);

void list(string curUser, int sock_desc);

void exitMainServer(string &curUser);

void transaction(string payer, string payee, string amount, string &curUser);

int main(int argc , char *argv[])
{
	if(argc != 2) {
		cout << "need to input port!\n";
		return 1;
	}


	int socket_desc , new_socket , c , *new_sock;
	struct sockaddr_in server , client;
	char *message;

	   
	
	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}
	
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( atoi(argv[1]) );
	
	//Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		puts("bind failed");
		return 1;
	}
	puts("bind done");
	
	//Listen
	listen(socket_desc , 3);
	
	//Accept and incoming connection
	puts("Waiting for incoming connections...");
	c = sizeof(struct sockaddr_in);
	while( (new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)) )
	{
		connection_num++;
		if(connection_num > 3) {
			string reply = "connection rejected - 3 clients connecting already";
			send(new_socket, reply.c_str(), reply.length(), 0);
			connection_num--;
			close(new_socket);
			continue;
		}

		else {
			puts("Connection accepted");
			string reply = "connected!";
			send(new_socket, reply.c_str(), reply.length(), 0);

			pthread_t sniffer_thread;
			new_sock = (int* )malloc(1);
			*new_sock = new_socket;

			ARGS arguments;
			arguments.client = &client;
			arguments.sock_desc = new_socket;
			ARGS *p = (ARGS *)malloc(sizeof *p);
			*p = arguments;
			
			if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) p) < 0)
			{
				perror("could not create thread");
				return 1;
			}
			
			puts("Handler assigned");
		}

		
	}
	
	if (new_socket<0)
	{
		perror("accept failed");
		return 1;
	}
	
	return 0;
}

/*
 * This will handle connection for each client
 * */
void *connection_handler(void *args)
{
	//Get the socket descriptor
	ARGS arguments = *(ARGS*)args;
	int read_size;
	char *message , client_message[2000];
	string curUser = "";

	
	//Receive a message from client
	while( (read_size = recv(arguments.sock_desc , client_message , 2000 , 0)) > 0 )
	{
		string r = client_message;
		cout << r << "\n";

		// list handler
		if(r == "List") {
			if(curUser != "") {
				list(curUser, arguments.sock_desc);
			}

			else {
				string reply = "401 please login first!";
				send(arguments.sock_desc, reply.c_str(), reply.length(), 0);
			}
		}

		// exit handler
		else if(r == "Exit") {
			exitMainServer(curUser);
		}

		// register, login or tansaction handler
		else {
			size_t pos = r.find("#");
			if (pos!=string::npos) { 
				string token = r.substr(0, pos);

				// register handler
				if(token == "REGISTER") { 

					string newuser = r.substr(pos+1, r.length());
					registerNewUser(newuser, arguments.client, arguments.sock_desc);
				}

				else {
					string rest = r.substr(pos+1, r.length());

					// login handler
					if(rest.find("#") == string::npos) { 
						string loginUser = token;
						string port = rest;

						login(loginUser, port, arguments.sock_desc, curUser);
					}

					// transaction handler
					else { 
						string payer = token;
						int del = rest.find("#");
						string amount = rest.substr(0, del);
						string payee = rest.substr(del+1, rest.length());

						transaction(payer, payee, amount, curUser);
					}

				}

			}

			else {
				cout << "none!\n";
			}
		}
		memset(client_message, 0, sizeof(client_message));
	}
	
		
	//Free the socket pointer
	
	
	return 0;
}

void registerNewUser(string username, sockaddr_in *client, int sock_desc) {

	int registered = false;
	for(USERLIST user : userlist)  {
		if(user.name == username) {
			registered = true;
			string reply = "210 FAIL";
    		send(sock_desc, reply.c_str(), reply.length(), 0);
			break;
		}
	}

	if(registered == false) {
		USERLIST newUser;

		newUser.name = username;
		char *tmp = inet_ntoa(client->sin_addr);
		string client_ip = tmp;
		newUser.ip = client_ip;
		newUser.port = ntohs(client->sin_port);
		newUser.online = false;
		newUser.balance = 10000;
		newUser.pk = "public key";

		// cout << "registering\n";
		userlist.push_back(newUser);

		string reply = "100 OK";
		send(sock_desc, reply.c_str(), reply.length(), 0);
	}	
}

void login(string loginUser, string port, int sock_desc, string &curUser) {
	// check if user is in list
	int registered = 0;
	for(USERLIST &user : userlist)  {
		if(user.name == loginUser) {
			registered = 1;
			user.online = true;
			user.users_port = stoi(port);
			user.socket_desc = sock_desc;
			curUser = loginUser;
			list(loginUser, sock_desc);
		}
	}
	if(registered == 0) {
		string reply = "220 AUTH_FAIL";
    	send(sock_desc, reply.c_str(), reply.length(), 0);
	}
}

void list(string curUser, int sock_desc) {
	string l = "";
	int accountBalance;
	string pk;
	int cnt = 0;

	for(USERLIST &user : userlist)  {
		if(user.online == true) {
			cnt++;
			string tmp = user.name + "#" + user.ip + "#" + to_string(user.users_port) + "\n";
			l+=tmp;
			if(user.name == curUser) {
				accountBalance = user.balance;
				pk = user.pk;
			}
		}
	}

	string r = to_string(accountBalance) + "\n" + pk + "\n" + to_string(cnt) + "\n" + l;
	send(sock_desc, r.c_str(), r.length(), 0);
}

void exitMainServer(string &curUser) {
	for(USERLIST &user : userlist)  {
		if(user.name == curUser) {
			user.online = false;
			curUser = "";

			break;
		}
	}

	mtx.lock();
	connection_num--;
	mtx.unlock();

	cout << connection_num << "\n";

	pthread_exit(NULL);

	
}

void transaction(string payer, string payee, string amount, string &curUser) {
	bool success =true;
	string reply;
	if(payee != curUser) {
		success = false;
		 reply = "transfer fail! Transfer message not sent from payee";
	}
	// check transfer the right person
	for(USERLIST &user : userlist)  {
		if(user.name == payer) {
			if(success && user.balance < stoi(amount)) {
				success = false;
				reply = "transfer fail! Not enough money:(";
			}

			if(!success) {
    			send(user.socket_desc, reply.c_str(), reply.length(), 0);
				break;
			}
			else {
				user.balance -= stoi(amount);
				string reply = "transfer Ok!";
				send(user.socket_desc, reply.c_str(), reply.length(), 0);
			}
		}
	}
	if(success) {
		for(USERLIST &user : userlist)  {
			if(user.name == payee) {
				user.balance += stoi(amount);
			}
		}
	}
}