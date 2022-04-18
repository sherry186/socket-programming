#include <stdio.h>
#include <stdlib.h>
#include <string.h> //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <pthread.h>
#include <map>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
using namespace std;

// ----------------- ssl functions ------------------ //

SSL_CTX *ctx;
SSL *ssl;
RSA *rsa_private;
SSL_CTX *ctx_client;
SSL *ssl_client;
FILE *fp;
#define RSA_CLIENT_KEY "client.key"
#define RSA_CLIENT_CERT "client.crt"
#define RSA_BLOCK_SIZE 256 - 12

#define MAX_RECV_LEN 1000
#define MAX_BUFFER_LEN 100 + 5
map<int, SSL *> socket_to_SSL;

SSL_CTX *InitClientCTX()
{
  SSL_CTX *ctx;
  /* SSL 庫初始化 */
  SSL_library_init();
  /* 載入所有 SSL 演算法 */
  OpenSSL_add_all_algorithms();
  /* 載入所有 SSL 錯誤訊息 */
  SSL_load_error_strings();
  /* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
  ctx = SSL_CTX_new(SSLv23_client_method());
  /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 單獨表示 V2 或 V3標準 */
  if (ctx == NULL)
  {
    ERR_print_errors_fp(stdout);
    abort();
  }
  return ctx;
}

void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{
  /* 載入使用者的數字證書， 此證書用來發送給客戶端。 證書裡包含有公鑰 */
  if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* 載入使用者私鑰 */
  if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* 檢查使用者私鑰是否正確 */
  if (!SSL_CTX_check_private_key(ctx))
  {
    fprintf(stderr, "Private key does not match the public certificate\n");
    abort();
  }
}

void ShowCerts(SSL *ssl)
{
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl);
  if (cert != NULL)
  {
    printf("Digital certificate information:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Certificate: %s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);
    X509_free(cert);
  }
  else
    printf("No certificate information！\n");
}

// ----------------- ssl functions end ------------------ //

string name;

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
  SSL_CTX *ctx = InitClientCTX();
  LoadCertificates(ctx, (char *)"client.crt", (char *)"client.key");

  // connect to main server
  // ------------------------------------------

  int sock_to_main_server = 0;
  struct sockaddr_in serv_addr;
  if ((sock_to_main_server = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    printf("\n Socket creation error \n");
    return 1;
  }

  if (argc != 3)
  {
    cout << "need to input ip and port! \n";
    return 1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
  serv_addr.sin_port = htons(atoi(argv[2]));

  if (connect(sock_to_main_server, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    printf("\nConnection Failed \n");
    return 1;
  }

  /* 基於 ctx 產生一個新的 SSL */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_load_verify_locations(ctx, "CA.pem", NULL);
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sock_to_main_server);

  /* 建立 SSL 連線 */
  if (SSL_connect(ssl) == -1)
  {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  else
  {
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    ShowCerts(ssl);
  }

  // main loop
  // ---------------------------------------------

  int server_fd;
  int ch;

  char reply[2000] = {0};
  // recv(sock_to_main_server, reply, sizeof(reply), 0);
  SSL_read(ssl, reply, sizeof(reply));

  printf("\n%s\n", reply);

  string r = reply;
  if (r != "connected!")
  {
    exit(0);
  }

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
  // send(sock_to_main_server, r.c_str(), r.length(), 0);
  SSL_write(ssl, r.c_str(), r.length());
  // recv(sock_to_main_server, reply, sizeof(reply), 0);
  SSL_read(ssl, reply, sizeof(reply));

  char *response_no = strtok(reply, " ");
  if (strcmp(response_no, "100") == 0)
  {
    printf("registered successfully!\n");
  }
  else if (strcmp(response_no, "210") == 0)
  {
    printf("Register failed!\n");
  }
  else
  {
    puts(reply);
  }
  // printf("\n%s\n", reply);
  printf("\n--------------------\n");
}

// login function
int login_to_server(int sock_to_main_server)
{
  int PORT;

  printf("Enter name: ");
  // scanf("%s", name);
  cin >> name;

  printf("Enter your port number: ");
  // scanf("%d", &PORT);
  cin >> PORT;

  int server_fd, new_socket, valread;
  struct sockaddr_in address;
  int k = 0;

  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    perror("socket failed");
    exit_network(sock_to_main_server);
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
    exit_network(sock_to_main_server);
    exit(EXIT_FAILURE);
  }
  if (listen(server_fd, 5) < 0)
  {
    perror("listen");
    exit_network(sock_to_main_server);
    exit(EXIT_FAILURE);
  }

  char reply[4000] = {0};

  string r;
  r = name + "#" + to_string(PORT);
  // send(sock_to_main_server, r.c_str(), r.length(), 0);
  SSL_write(ssl, r.c_str(), r.length());
  // recv(sock_to_main_server, reply, sizeof(reply), 0);
  SSL_read(ssl, reply, sizeof(reply));

  printf("\n%s\n", reply);

  pthread_t tid;
  int server_fd_sock[2] = {server_fd, sock_to_main_server};
  pthread_create(&tid, NULL, &receive_thread, &server_fd_sock); //Creating thread to keep receiving message in real time
  printf("\n--------------------\n");
  return server_fd;
}

// list function
void list(int sock_to_main_server)
{
  char reply[4000];

  string r = "List";
  // send(sock_to_main_server, r.c_str(), r.length(), 0);
  SSL_write(ssl, r.c_str(), r.length());

  // recv(sock_to_main_server, reply, sizeof(reply), 0);
  SSL_read(ssl, reply, 4000);
  printf("\n%s\n", reply);
  printf("\n--------------------\n");
}

// transaction function
void transaction(int sock_to_main_server)
{
  char reply[4000] = {0};

  string r = "List";
  // send(sock_to_main_server, r.c_str(), r.length(), 0);
  // recv(sock_to_main_server, reply, sizeof(reply), 0);
  SSL_write(ssl, r.c_str(), r.length());
  SSL_read(ssl, reply, sizeof(reply));
  printf("\n%s\n", reply);

  char *response_no = strtok(reply, " ");
  if (strcmp(response_no, "401") == 0)
  {
    printf("\n--------------------\n");
    return;
  }

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

  /** Encrypt **/
  FILE *key_file = fopen(RSA_CLIENT_KEY, "r");
  RSA *privateKey = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
  unsigned char *buf = (unsigned char *)malloc(RSA_size(privateKey));
  int err = RSA_private_encrypt((strlen(r.c_str()) + 1) * sizeof(char), (unsigned char *)r.c_str(), buf, privateKey, RSA_PKCS1_PADDING);
  if (err == -1)
  {
    ERR_print_errors_fp(stderr);
  }

  // socket connection
  int sock = 0, valread;
  struct sockaddr_in serv_addr;
  char hello[1024] = {0};
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    printf("\n Socket creation error \n");
    return;
  }

  SSL *ssl_peer;
  /* Create an SSL_METHOD structure (choose an SSL/TLS protocol version) */
  SSL_METHOD *meth = (SSL_METHOD *)TLS_method();

  /* Create an SSL_CTX structure */
  SSL_CTX *ctx = SSL_CTX_new(meth);

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY; //INADDR_ANY always gives an IP of 0.0.0.0
  serv_addr.sin_port = htons(PORT_payee);

  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    printf("\nConnection Failed \n");
    return;
  }

  /* An SSL structure is created */
  ssl_peer = SSL_new(ctx);
  /* Assign the socket into the SSL structure (SSL and socket without BIO) */
  if (SSL_use_certificate_file(ssl_peer, RSA_CLIENT_CERT, SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
    exit(1);
  }

  /* Load the private-key corresponding to the client certificate */
  if (SSL_use_PrivateKey_file(ssl_peer, RSA_CLIENT_KEY, SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
    exit(1);
  }

  /* Check if the client certificate and private-key matches */
  if (!SSL_check_private_key(ssl_peer))
  {
    fprintf(stderr, "Private key does not match the certificate public key\n ");
    exit(1);
  }

  SSL_set_fd(ssl_peer, sock);
  err = SSL_connect(ssl_peer);

  if (err == -1)
  {
    printf("Connection error");
    exit(1);
  }
  else
  {
    SSL_write(ssl_peer, buf, RSA_size(privateKey));
    // SSL_write(ssl_peer, r.c_str(), r.length());
    // send(sock, r.c_str(), r.length(), 0);
    free(buf);
    buf = NULL;

    memset(reply, 0, sizeof(reply));
    // int tmp = recv(sock_to_main_server, reply, sizeof(reply), 0);
    int tmp = SSL_read(ssl, reply, sizeof(reply));
    printf("\n%s\n", reply);
    printf("\n--------------------\n");
  }
}

// exit function
void exit_network(int sock_to_main_server)
{
  char reply[2000] = {0};

  string r = "Exit";
  // send(sock_to_main_server, r.c_str(), r.length(), 0);
  SSL_write(ssl, r.c_str(), r.length());
  // recv(sock_to_main_server, reply, sizeof(reply), 0);
  // printf("\n%s\n", reply);
  close(sock_to_main_server);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  printf("\nsee you again!\n");
  printf("\n--------------------\n");

  exit(0);
}

//Calling receiving every 2 seconds
void *receive_thread(void *serverfd_sock)
{
  int *s_fd_sock = (int *)serverfd_sock;
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
          SSL *ssl_peer;
          /* Create an SSL_METHOD structure (choose an SSL/TLS protocol version) */
          SSL_METHOD *meth = (SSL_METHOD *)TLS_method();

          /* Create an SSL_CTX structure */
          SSL_CTX *ctx = SSL_CTX_new(meth);

          /* Load the client certificate into the SSL_CTX structure */
          if (SSL_CTX_use_certificate_file(ctx, RSA_CLIENT_CERT, SSL_FILETYPE_PEM) <= 0)
          {
            ERR_print_errors_fp(stderr);
            exit(1);
          }

          /* Load the private-key corresponding to the client certificate */
          if (SSL_CTX_use_PrivateKey_file(ctx, RSA_CLIENT_KEY, SSL_FILETYPE_PEM) <= 0)
          {
            ERR_print_errors_fp(stderr);
            exit(1);
          }

          /* Check if the client certificate and private-key matches */
          if (!SSL_CTX_check_private_key(ctx))
          {
            fprintf(stderr, "Private key does not match the certificate public key\n ");
            exit(1);
          }

          int client_socket;

          if ((client_socket = accept(server_fd, (struct sockaddr *)&address,
                                      (socklen_t *)&addrlen)) < 0)
          {
            perror("accept");
            exit(EXIT_FAILURE);
          }

          SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
          SSL_CTX_load_verify_locations(ctx, "CA.pem", NULL);
          ssl_peer = SSL_new(ctx);

          /* Assign the socket into the SSL structure (SSL and socket without BIO) */
          SSL_set_fd(ssl_peer, client_socket);

          /* Perform SSL Handshake on the SSL server */
          int err = SSL_accept(ssl_peer);

          // cout << err << "\n";
          if (err <= 0)
          {
            ERR_print_errors_fp(stderr);
          }

          FD_SET(client_socket, &current_sockets);
          socket_to_SSL.insert(pair<int, SSL *>(client_socket, ssl_peer));
        }
        else
        {
          memset(buffer, 0, sizeof(buffer));
          // valread = recv(i, buffer, sizeof(buffer), 0);
          auto iter = socket_to_SSL.find(i);
          SSL *ssl_peer = iter->second;
          SSL_read(ssl_peer, buffer, sizeof(buffer));
          string plaintext;
          plaintext = buffer;
          // cout << r;
          // printf("\n%s\n", buffer);
          // send(sock_to_main_server, r.c_str(), r.length(), 0);

          /*** Certificate ***/
          X509 *peer_cert = SSL_get_peer_certificate(ssl_peer);
          if (peer_cert == NULL)
          {
            printf("No Certificate Received\n");
          }
          EVP_PKEY *peer_pubkey = X509_get_pubkey(peer_cert);
          /****************/

          /*** Decrypt ***/
          unsigned char *peer_msg_plain = (unsigned char *)malloc(MAX_RECV_LEN);
          ;
          RSA *peer_rsa_pubkey = EVP_PKEY_get1_RSA(peer_pubkey);

          int err = RSA_public_decrypt(RSA_size(peer_rsa_pubkey), (unsigned char *)buffer, peer_msg_plain, peer_rsa_pubkey, RSA_PKCS1_PADDING);
          if (err == -1)
          {
            ERR_print_errors_fp(stderr);
          }
          /***************/
          string test = (char *)peer_msg_plain;
          // cout << "encrypt mess = " << test << "\n";

          /**** Encrypt ****/
          FILE *key_file = fopen(RSA_CLIENT_KEY, "r");
          RSA *privateKey = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
          unsigned char *cipher_text1 = (unsigned char *)malloc(RSA_size(privateKey));
          unsigned char *cipher_text2 = (unsigned char *)malloc(RSA_size(privateKey));
          unsigned char *to_server = (unsigned char *)malloc(MAX_BUFFER_LEN * sizeof(char) + 2 * RSA_size(privateKey));
          unsigned char *peer_msg1 = (unsigned char *)malloc(RSA_size(privateKey));
          unsigned char *peer_msg2 = (unsigned char *)malloc(RSA_size(privateKey));
          copy(buffer, buffer + RSA_BLOCK_SIZE, peer_msg1);
          // memcpy(peer_msg1, buffer, (RSA_BLOCK_SIZE));
          copy(buffer + RSA_BLOCK_SIZE, buffer + RSA_size(privateKey), peer_msg2);
          // memcpy(peer_msg2, buffer + (RSA_BLOCK_SIZE), RSA_size(privateKey) - (RSA_BLOCK_SIZE));
          err = RSA_private_encrypt((RSA_BLOCK_SIZE), (unsigned char *)peer_msg1, cipher_text1, privateKey, RSA_PKCS1_PADDING);
          if (err == -1)
          {
            ERR_print_errors_fp(stderr);
          }
          err = RSA_private_encrypt(RSA_size(privateKey) - (RSA_BLOCK_SIZE), (unsigned char *)peer_msg2, cipher_text2, privateKey, RSA_PKCS1_PADDING);
          if (err == -1)
          {
            ERR_print_errors_fp(stderr);
          }
          // err = RSA_private_encrypt((RSA_BLOCK_SIZE), (unsigned char *)peer_msg1.c_str(), cipher_text1, privateKey, RSA_PKCS1_PADDING);
          // if (err == -1)
          // {
          //   ERR_print_errors_fp(stderr);
          // }
          // err = RSA_private_encrypt(RSA_size(privateKey) - (RSA_BLOCK_SIZE), (unsigned char *)peer_msg2.c_str(), cipher_text2, privateKey, RSA_PKCS1_PADDING);
          // if (err == -1)
          // {
          //   ERR_print_errors_fp(stderr);
          // }

          // string cipher_text_string1 = (char *)cipher_text1;
          // string cipher_text_string2 = (char *)cipher_text2;
          // string to_server = test + "&" + cipher_text_string1 + cipher_text_string2;

          // strcpy(to_server, (char *)peer_msg_plain);
          to_server[0] = 'T';
          copy(peer_msg_plain, peer_msg_plain + sizeof(peer_msg_plain), to_server + 1);
          // memcpy(to_server + strlen((char *)peer_msg_plain), (char *)cipher_text1, RSA_size(privateKey));
          to_server[sizeof(peer_msg_plain) + 1] = '&';
          copy(cipher_text1, cipher_text1 + RSA_size(privateKey), (to_server + 1) + sizeof(peer_msg_plain) + 1);
          // memcpy(to_server + strlen((char *)peer_msg_plain) + RSA_size(privateKey), (char *)cipher_text2, RSA_size(privateKey));
          copy(cipher_text2, cipher_text2 + RSA_size(privateKey), (to_server + 1) + sizeof(peer_msg_plain) + 1 + RSA_size(privateKey));
          SSL_write(ssl, to_server, MAX_BUFFER_LEN * sizeof(char) + 2 * RSA_size(privateKey));
          FD_CLR(i, &current_sockets);

          // for (int i = 0; i < MAX_BUFFER_LEN * sizeof(char) + 2 * RSA_size(privateKey); i++)
          // {
          //   cout << to_server[i];
          // }
          // cout << "\n";

          free(peer_msg_plain);
          peer_msg_plain = NULL;
          free(cipher_text1);
          cipher_text1 = NULL;
          free(cipher_text2);
          cipher_text2 = NULL;
          free(peer_msg1);
          peer_msg1 = NULL;
          free(peer_msg2);
          peer_msg2 = NULL;
          free(to_server);
          to_server = NULL;
        }
      }
    }

    if (k == (FD_SETSIZE * 2))
      break;
  }
}
