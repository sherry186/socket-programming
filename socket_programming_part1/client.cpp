#include<stdio.h>
#include <stdlib.h>
#include<string.h>	//strlen
#include<sys/socket.h>
#include<arpa/inet.h>	//inet_addr
#include<cstring>
#include <iostream>
#include <unistd.h>
#include <pthread.h>
using namespace std;

string name;
int PORT;

void sending();
void register_to_server(int sock_to_main_server);
int login_to_server(int sock_to_main_server);
void list(int sock_to_main_server);
void transaction(int sock_to_main_server);
void exit_network(int sock_to_main_server);
void receiving(int server_fd, int sock);
void *receive_thread(void *server_fd);


int main(int argc, char const *argv[])
{

// connect to main server
// ------------------------------------------

    int sock_to_main_server = 0;
    struct sockaddr_in serv_addr;
    if ((sock_to_main_server = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return 1;
    }

    if(argc != 3){
        cout << "need to input ip and port! \n";
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr( argv[1] ); //INADDR_ANY always gives an IP of 0.0.0.0
    serv_addr.sin_port = htons( atoi(argv[2]) );

    if (connect(sock_to_main_server, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return 1;
    }


// main loop
// ---------------------------------------------

    int server_fd;
    int ch;

    printf("\n*****At any point in time press the following:*****\n1.Register\n2.Login\n3.List\n4.Transaction\n5.Exit\n");
    printf("\nEnter choice: ");
    do
    {

        scanf("%d", &ch);
        switch (ch)
        {
        case 0:
            printf("\nLeaving\n");
            break;
        case 1:
            register_to_server(sock_to_main_server);
            break;
        case 2:
            server_fd = login_to_server(sock_to_main_server);
            break;
        case 3:
            list(sock_to_main_server);
            break;
        case 4:
            transaction(sock_to_main_server);
            break;
        case 5:
            exit_network(sock_to_main_server);
            break;
        default:
            printf("\nWrong choice\n");
        }
    } while (ch);

    close(server_fd);

    return 0;
}


// helper functions
// -----------------------------------------------

// register function
void register_to_server(int sock_to_main_server)
{

    char reply[2000] = {0};

    printf("Enter name: ");
    // scanf("%s", name);
    cin >> name;

    string r = "REGISTER#" + name;
    send(sock_to_main_server , r.c_str() , r.length() , 0);
    recv(sock_to_main_server, reply , sizeof(reply) , 0);

    char *response_no = strtok(reply, " ");
    if (strcmp(response_no, "100") == 0)
    {
        printf("registered successfully!\n");
    }
    else if (strcmp(response_no, "210") == 0)
    {
        printf("Register failed!\n");
    }
    // printf("\n%s\n", reply);
    printf("\n--------------------\n");
}

// login function
int login_to_server(int sock_to_main_server)
{
    char reply[2000] = {0};

    printf("Enter name: ");
    // scanf("%s", name);
    cin >> name;
    
    printf("Enter your port number: ");
    // scanf("%d", &PORT);
    cin >> PORT;

    string r;
    r = name + "#" + to_string(PORT);
    send(sock_to_main_server , r.c_str() , r.length() , 0);
    recv(sock_to_main_server, reply , sizeof(reply) , 0);

    
    printf("\n%s\n", reply);

    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int k = 0;

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    // Forcefully attaching socket to the port

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // //Printed the server socket addr and port
    // printf("IP address is: %s\n", inet_ntoa(address.sin_addr));
    // printf("port is: %d\n", (int)ntohs(address.sin_port));

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 5) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    pthread_t tid;
    int server_fd_sock[2] = {server_fd, sock_to_main_server};
    pthread_create(&tid, NULL, &receive_thread, &server_fd_sock); //Creating thread to keep receiving message in real time
    printf("\n--------------------\n");
    return server_fd;
}

// list function
void list(int sock_to_main_server)
{
    char reply[2000] = {0};

    string r = "List";
    send(sock_to_main_server, r.c_str(), r.length(), 0);
    recv(sock_to_main_server, reply, sizeof(reply), 0);
    printf("\n%s\n", reply);
    printf("\n--------------------\n");
}

// transaction function
void transaction(int sock_to_main_server)
{
    char reply[2000] = {0};

    string r = "List";
    send(sock_to_main_server, r.c_str(), r.length(), 0);
    recv(sock_to_main_server, reply, sizeof(reply), 0);
    printf("\n%s\n", reply);


    int PORT_payee;
    string payeeName;

    printf("Enter payee name: ");
    cin >> payeeName;

    printf("enter port number of payee: "); 
    cin >> PORT_payee;

    
    int amount;
    printf("enter amount: "); 
    cin >> amount;

    // memset(buffer, 0, sizeof(buffer));
    r.clear();
    r = name + "#" + to_string(amount) + "#" + payeeName;


    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char hello[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY; //INADDR_ANY always gives an IP of 0.0.0.0
    serv_addr.sin_port = htons(PORT_payee);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return;
    }

    send(sock, r.c_str(), r.length(), 0);
    close(sock);

    memset(reply, 0, sizeof(reply));
    int tmp = recv(sock_to_main_server, reply, sizeof(reply), 0);
    printf("\n%s\n", reply);
    printf("\n--------------------\n");
}

// exit function
void exit_network(int sock_to_main_server)
{
    char reply[2000] = {0};

    string r = "Exit";
    send(sock_to_main_server, r.c_str(), r.length(), 0);
    // recv(sock_to_main_server, reply, sizeof(reply), 0);
    // printf("\n%s\n", reply);
    close(sock_to_main_server);
    printf("\nsee you again!\n");
    printf("\n--------------------\n");
    exit(0);
}

//Calling receiving every 2 seconds
void *receive_thread(void *serverfd_sock)
{
    int* s_fd_sock = (int *)serverfd_sock;
    while (1)
    {
        sleep(2);
        receiving(s_fd_sock[0], s_fd_sock[1]);
    }
}

//Receiving messages on our port
void receiving(int server_fd, int sock_to_main_server)
{
    struct sockaddr_in address;
    int valread;
    char buffer[2000] = {0};
    int addrlen = sizeof(address);
    fd_set current_sockets, ready_sockets;

    //Initialize my current set
    FD_ZERO(&current_sockets);
    FD_SET(server_fd, &current_sockets);
    int k = 0;
    while (1)
    {
        k++;
        ready_sockets = current_sockets;

        if (select(FD_SETSIZE, &ready_sockets, NULL, NULL, NULL) < 0)
        {
            perror("Error");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < FD_SETSIZE; i++)
        {
            if (FD_ISSET(i, &ready_sockets))
            {

                if (i == server_fd)
                {
                    int client_socket;

                    if ((client_socket = accept(server_fd, (struct sockaddr *)&address,
                                                (socklen_t *)&addrlen)) < 0)
                    {
                        perror("accept");
                        exit(EXIT_FAILURE);
                    }
                    FD_SET(client_socket, &current_sockets);
                }
                else
                {
                    memset(buffer, 0, sizeof(buffer));
                    valread = recv(i, buffer, sizeof(buffer), 0);
                    string r;
                    r = buffer;
                    // cout << r;
                    // printf("\n%s\n", buffer);
                    send(sock_to_main_server, r.c_str(), r.length(), 0);
                    FD_CLR(i, &current_sockets);
                }
            }
        }

        if (k == (FD_SETSIZE * 2))
            break;
    }
}

