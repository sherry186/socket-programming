#include <stdio.h>
#include <stdlib.h>
#include <string.h> //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <pthread.h>
#include <vector>
#include <string>
#include <mutex>
#include <algorithm>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

using namespace std;

#define RSA_BLOCK_SIZE 256 - 12
#define KEY_SIZE 256
#define MAX_RECV_LEN 1000
#define MAX_BUFFER_LEN 100

// ----------------- ssl functions ------------------ //

SSL_CTX *InitServerCTX()
{
  SSL_CTX *ctx;
  /* SSL 庫初始化 */
  SSL_library_init();
  /* 載入所有 SSL 演算法 */
  OpenSSL_add_all_algorithms();
  /* 載入所有 SSL 錯誤訊息 */
  SSL_load_error_strings();
  /* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
  ctx = SSL_CTX_new(SSLv23_server_method());
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

// ----------------- ssl functions ------------------ //

mutex mtx;

int connection_num = 0;

struct USERLIST
{
  string name;
  string ip;
  int port;
  int users_port;
  bool online;
  int balance;
  string pk;
  int socket_desc;
  SSL *ssl;
  RSA *public_key;
};
vector<USERLIST> userlist;

struct ARGS
{
  sockaddr_in *client;
  int sock_desc;
  SSL *ssl;
};

void *connection_handler(void *);

void registerNewUser(string username, sockaddr_in *client, int sock_desc, SSL *ssl);

void login(string loginUser, string port, int sock_desc, string &curUser, SSL *ssl);

void list(string curUser, int sock_desc, SSL *ssl);

void exitMainServer(string &curUser, int sock_desc, SSL *ssl);

void transaction(string payer, string payee, string amount, string &curUser);

int main(int argc, char *argv[])
{
  if (argc != 2)
  {
    cout << "need to input port!\n";
    return 1;
  }

  int socket_desc, new_socket, c, *new_sock;
  struct sockaddr_in server, client;
  char *message;

  SSL_CTX *ctx = InitServerCTX();
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_load_verify_locations(ctx, "CA.pem", NULL);
  LoadCertificates(ctx, (char *)"server.crt", (char *)"server.key");

  //Create socket
  socket_desc = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_desc == -1)
  {
    printf("Could not create socket");
  }

  //Prepare the sockaddr_in structure
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons(atoi(argv[1]));

  //Bind
  if (bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
  {
    puts("bind failed");
    return 1;
  }
  puts("bind done");

  //Listen
  listen(socket_desc, 3);

  //Accept and incoming connection
  puts("Waiting for incoming connections...");
  c = sizeof(struct sockaddr_in);
  while ((new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t *)&c)))
  {
    /* 將連線使用者的 socket 加入到 SSL */
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_socket);
    /* 建立 SSL 連線 */
    if (SSL_accept(ssl) == -1)
    {
      ERR_print_errors_fp(stderr);
      close(new_socket);
      continue;
    }
    ShowCerts(ssl);

    connection_num++;
    if (connection_num > 3)
    {
      string reply = "connection rejected - 3 clients connecting already";
      send(new_socket, reply.c_str(), reply.length(), 0);
      connection_num--;
      close(new_socket);
      continue;
    }

    else
    {
      puts("Connection accepted");
      string reply = "connected!";
      // send(new_socket, reply.c_str(), reply.length(), 0);
      SSL_write(ssl, reply.c_str(), reply.length());

      pthread_t sniffer_thread;
      new_sock = (int *)malloc(1);
      *new_sock = new_socket;

      ARGS arguments;
      arguments.client = &client;
      arguments.sock_desc = new_socket;
      arguments.ssl = ssl;
      ARGS *p = (ARGS *)malloc(sizeof *p);
      *p = arguments;

      if (pthread_create(&sniffer_thread, NULL, connection_handler, (void *)p) < 0)
      {
        perror("could not create thread");
        return 1;
      }

      puts("Handler assigned");
    }
  }

  if (new_socket < 0)
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
  ARGS arguments = *(ARGS *)args;
  int read_size;
  char *message, client_message[2000];
  string curUser = "";

  //Receive a message from client
  // while ((read_size = recv(arguments.sock_desc, client_message, 2000, 0)) > 0)
  while ((read_size = SSL_read(arguments.ssl, client_message, sizeof(client_message))) > 0)
  {
    // for (int i = 0; i < sizeof(client_message); i++)
    // {
    //   cout << client_message[i];
    // }
    // cout << "\n";

    if (client_message[0] == 'T')
    {
      unsigned char *cipher = find((unsigned char *)client_message, (unsigned char *)client_message + sizeof(client_message), '&');
      *cipher = '\0';
      cipher++;
      // char *cipher = strchr(client_message, '&') + 1;

      // *strchr(client_message, '&') = '\0'; // let req end

      string plaintext = client_message;
      // cout << "parsed client message" << plaintext << "\n";
      int del = plaintext.find("#");
      string payer = plaintext.substr(1, del - 1);
      string rest = plaintext.substr(del + 1, string::npos);
      int del2 = rest.find("#");
      string amount = rest.substr(0, del2);
      string payee = rest.substr(del2 + 1, string::npos);
      // string encrypt = rest.substr(del2 + 1, rest.length());

      // cout << "encrypt = " << encrypt << "\n";
      cout << payer << " " << amount << " " << payee << "\n";

      RSA *payee_rsa_pubkey, *payer_rsa_pubkey;

      for (USERLIST &user : userlist)
      {
        if (user.name == payer)
        {
          payer_rsa_pubkey = user.public_key;
        }
        if (user.name == payee)
        {
          payee_rsa_pubkey = user.public_key;
        }
      }

      // cout << "debug in saved public key\n";

      unsigned char *text = (unsigned char *)malloc(RSA_size(payee_rsa_pubkey));
      unsigned char *text_2 = (unsigned char *)malloc(RSA_size(payee_rsa_pubkey));

      // cout << "before decrypt B1\n";

      int err = RSA_public_decrypt(RSA_size(payee_rsa_pubkey), (unsigned char *)cipher, text, payee_rsa_pubkey, RSA_PKCS1_PADDING);
      if (err == -1)
      {
        printf("1\n");
        ERR_print_errors_fp(stderr);
        // strcpy(responseBuffer, "240 TX_DENIAL");
        // SSL_write(ssl, responseBuffer, sizeof(responseBuffer));
        exit(1);
      }

      // cout << "before decrypt B2\n";
      err = RSA_public_decrypt(RSA_size(payee_rsa_pubkey), (unsigned char *)cipher + RSA_size(payee_rsa_pubkey), text + RSA_BLOCK_SIZE, payee_rsa_pubkey, RSA_PKCS1_PADDING);
      if (err == -1)
      {
        printf("2\n");
        ERR_print_errors_fp(stderr);
        // strcpy(responseBuffer, "240 TX_DENIAL");
        // SSL_write(ssl, responseBuffer, sizeof(responseBuffer));
        exit(1);
      }
      // cout << "before decrypt A\n";
      err = RSA_public_decrypt(RSA_size(payer_rsa_pubkey), text, text_2, payer_rsa_pubkey, RSA_PKCS1_PADDING);
      if (err == -1)
      {
        printf("3\n");
        ERR_print_errors_fp(stderr);
        // strcpy(responseBuffer, "240 TX_DENIAL");
        // SSL_write(ssl, responseBuffer, sizeof(responseBuffer));
        exit(1);
      }

      if (memcmp(text_2, &client_message[1], sizeof(text_2)) == 0)
      {
        transaction(payer, payee, amount, curUser);
      }
      else
      {
        string reply = "transfer fail";

        for (USERLIST &user : userlist)
        {
          if (user.name == payer)
          {
            SSL_write(user.ssl, reply.c_str(), reply.length());
            break;
          }
        }
      }

      // for (int i = 0; i < sizeof(text_2); i++)
      // {
      //   cout << text_2[i];
      // }
      // cout << "\n";
      // if (err == -1 || strcmp(client_message, (char *)text_2) != 0)
      // {
      //   printf("3\n");
      //   ERR_print_errors_fp(stderr);
      //   // strcpy(responseBuffer, "240 TX_DENIAL");
      //   // SSL_write(ssl, responseBuffer, sizeof(responseBuffer));
      //   exit(1);
      // }

      // unsigned char *text = (unsigned char *)malloc(RSA_size(payee_rsa_pubkey));
      // unsigned char *text = (unsigned char *)malloc(RSA_size(payee_rsa_pubkey));

      // int err = RSA_public_decrypt(RSA_size(payee_rsa_pubkey), encrypt, text, payee_rsa_pubkey, RSA_PKCS1_PADDING);
      // if (err == -1)
      // {
      //   ERR_print_errors_fp(stderr);
      // }

      // unsigned char *plain = (unsigned char *)malloc(RSA_size(payer_rsa_pubkey));
      // err = RSA_public_decrypt(RSA_size(payer_rsa_pubkey), text, plain, payer_rsa_pubkey, RSA_PKCS1_PADDING);
      // if (err == -1)
      // {
      //   ERR_print_errors_fp(stderr);
      // }

      // string plain_string = (char *)plain;

      // cout << "decrypted = " << plain_string << "\n";
    }

    else
    {
      string r = client_message;
      // cout << "client_message = " << r << "\n";

      // list handler
      if (r == "List")
      {
        if (curUser != "")
        {
          list(curUser, arguments.sock_desc, arguments.ssl);
        }

        else
        {
          string reply = "401 please login first!";
          // send(arguments.sock_desc, reply.c_str(), reply.length(), 0);
          SSL_write(arguments.ssl, reply.c_str(), reply.length());
        }
      }

      // exit handler
      else if (r == "Exit")
      {
        exitMainServer(curUser, arguments.sock_desc, arguments.ssl);
      }

      // register, login or tansaction handler
      else
      {
        size_t pos = r.find("#");
        if (pos != string::npos)
        {
          string token = r.substr(0, pos);

          // register handler
          if (token == "REGISTER")
          {

            string newuser = r.substr(pos + 1, r.length());
            registerNewUser(newuser, arguments.client, arguments.sock_desc, arguments.ssl);
          }

          else
          {
            string rest = r.substr(pos + 1, r.length());

            // login handler
            if (rest.find("#") == string::npos)
            {
              string loginUser = token;
              string port = rest;

              login(loginUser, port, arguments.sock_desc, curUser, arguments.ssl);
            }

            // transaction handler
            else
            {
              // string payer = token;
              // int del = rest.find("#");
              // string amount = rest.substr(0, del);
              // int del2 = rest.find("&");
              // string payee = rest.substr(del + 1, del2);
              // // string encrypt = rest.substr(del2 + 1, rest.length());

              // // cout << "encrypt = " << encrypt << "\n";
              // cout << payer << " " << amount << " " << payee << "\n";

              // RSA *payee_rsa_pubkey, *payer_rsa_pubkey;

              // for (USERLIST &user : userlist)
              // {
              //   if (user.name == payer)
              //   {
              //     payer_rsa_pubkey = user.public_key;
              //   }
              //   if (user.name == payee)
              //   {
              //     payee_rsa_pubkey = user.public_key;
              //   }
              // }

              // // cout << "debug in saved public key\n";

              // // unsigned char *text = (unsigned char *)malloc(RSA_BLOCK_SIZE);
              // // unsigned char *text_2 = (unsigned char *)malloc(MAX_RECV_LEN);

              // // cout << "before decrypt B1\n";

              // // int err = RSA_public_decrypt(RSA_size(payee_rsa_pubkey), (unsigned char *)cipher, text, payee_rsa_pubkey, RSA_PKCS1_PADDING);
              // // if (err == -1)
              // // {
              // //   printf("1\n");
              // //   ERR_print_errors_fp(stderr);
              // //   // strcpy(responseBuffer, "240 TX_DENIAL");
              // //   // SSL_write(ssl, responseBuffer, sizeof(responseBuffer));
              // //   exit(1);
              // // }

              // // cout << "before decrypt B2\n";
              // // err = RSA_public_decrypt(RSA_size(payee_rsa_pubkey), (unsigned char *)cipher + RSA_size(payee_rsa_pubkey), text + RSA_BLOCK_SIZE, payee_rsa_pubkey, RSA_PKCS1_PADDING);
              // // if (err == -1)
              // // {
              // //   printf("2\n");
              // //   ERR_print_errors_fp(stderr);
              // //   // strcpy(responseBuffer, "240 TX_DENIAL");
              // //   // SSL_write(ssl, responseBuffer, sizeof(responseBuffer));
              // //   exit(1);
              // // }
              // // cout << "before decrypt A\n";
              // // err = RSA_public_decrypt(RSA_size(payer_rsa_pubkey), text, text_2, payer_rsa_pubkey, RSA_PKCS1_PADDING);
              // // if (err == -1 || strcmp(client_message, (char *)text_2) != 0)
              // // {
              // //   printf("3\n");
              // //   ERR_print_errors_fp(stderr);
              // //   // strcpy(responseBuffer, "240 TX_DENIAL");
              // //   // SSL_write(ssl, responseBuffer, sizeof(responseBuffer));
              // //   exit(1);
              // // }

              // // unsigned char *text = (unsigned char *)malloc(RSA_size(payee_rsa_pubkey));
              // // unsigned char *text = (unsigned char *)malloc(RSA_size(payee_rsa_pubkey));

              // // int err = RSA_public_decrypt(RSA_size(payee_rsa_pubkey), encrypt, text, payee_rsa_pubkey, RSA_PKCS1_PADDING);
              // // if (err == -1)
              // // {
              // //   ERR_print_errors_fp(stderr);
              // // }

              // // unsigned char *plain = (unsigned char *)malloc(RSA_size(payer_rsa_pubkey));
              // // err = RSA_public_decrypt(RSA_size(payer_rsa_pubkey), text, plain, payer_rsa_pubkey, RSA_PKCS1_PADDING);
              // // if (err == -1)
              // // {
              // //   ERR_print_errors_fp(stderr);
              // // }

              // // string plain_string = (char *)plain;

              // // cout << "decrypted = " << plain_string << "\n";

              // transaction(payer, payee, amount, curUser);
            }
          }
        }
        else
        {
          cout << "none!\n";
        }
      }
    }
    memset(client_message, 0, sizeof(client_message));
  }

  return 0;
}

void registerNewUser(string username, sockaddr_in *client, int sock_desc, SSL *ssl)
{

  int registered = false;
  for (USERLIST user : userlist)
  {
    if (user.name == username)
    {
      registered = true;
      string reply = "210 FAIL";
      // send(sock_desc, reply.c_str(), reply.length(), 0);
      SSL_write(ssl, reply.c_str(), reply.length());
      break;
    }
  }

  if (registered == false)
  {
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
    // send(sock_desc, reply.c_str(), reply.length(), 0);
    SSL_write(ssl, reply.c_str(), reply.length());
  }
}

void login(string loginUser, string port, int sock_desc, string &curUser, SSL *ssl)
{
  // check if user is in list
  int registered = 0;
  for (USERLIST &user : userlist)
  {
    if (user.name == loginUser)
    {
      registered = 1;
      user.online = true;
      user.users_port = stoi(port);
      user.socket_desc = sock_desc;
      user.ssl = ssl;
      curUser = loginUser;

      // 存取 public key
      X509 *cert = SSL_get_peer_certificate(ssl);
      EVP_PKEY *public_key = X509_get_pubkey(cert);
      RSA *rsa_publicKey = EVP_PKEY_get1_RSA(public_key);

      user.public_key = rsa_publicKey;
      list(loginUser, sock_desc, ssl);
    }
  }
  if (registered == 0)
  {
    string reply = "220 AUTH_FAIL";
    // send(sock_desc, reply.c_str(), reply.length(), 0);
    SSL_write(ssl, reply.c_str(), reply.length());
  }
}

void list(string curUser, int sock_desc, SSL *ssl)
{
  string l = "";
  int accountBalance;
  string pk;
  int cnt = 0;

  for (USERLIST &user : userlist)
  {
    if (user.online == true)
    {
      cnt++;
      string tmp = user.name + "#" + user.ip + "#" + to_string(user.users_port) + "\n";
      l += tmp;
      if (user.name == curUser)
      {
        accountBalance = user.balance;
        X509 *cert = SSL_get_peer_certificate(ssl);
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        puts(line);
        string line_string = line;
        pk = line_string;
      }
    }
  }

  string r = to_string(accountBalance) + "\n" + pk + "\n" + to_string(cnt) + "\n" + l;
  // send(sock_desc, r.c_str(), r.length(), 0);
  SSL_write(ssl, r.c_str(), r.length());
}

void exitMainServer(string &curUser, int sock_desc, SSL *ssl)
{
  for (USERLIST &user : userlist)
  {
    if (user.name == curUser)
    {
      user.online = false;
      curUser = "";

      break;
    }
  }

  mtx.lock();
  connection_num--;
  mtx.unlock();

  cout << connection_num << "\n";

  //Free the socket pointer
  /* 關閉 SSL 連線 */
  SSL_shutdown(ssl);
  /* 釋放 SSL */
  SSL_free(ssl);
  /* 關閉 socket */
  close(sock_desc);

  pthread_exit(NULL);
}

void transaction(string payer, string payee, string amount, string &curUser)
{
  bool success = true;
  string reply;
  if (payee != curUser)
  {
    success = false;
    reply = "transfer fail! Transfer message not sent from payee";
  }
  // check transfer the right person
  for (USERLIST &user : userlist)
  {
    if (user.name == payer)
    {
      if (success && user.balance < stoi(amount))
      {
        success = false;
        reply = "transfer fail! Not enough money:(";
      }

      if (!success)
      {
        // send(user.socket_desc, reply.c_str(), reply.length(), 0);
        SSL_write(user.ssl, reply.c_str(), reply.length());
        break;
      }
      else
      {
        user.balance -= stoi(amount);
        string reply = "transfer Ok!";
        // send(user.socket_desc, reply.c_str(), reply.length(), 0);
        SSL_write(user.ssl, reply.c_str(), reply.length());
      }
    }
  }
  if (success)
  {
    for (USERLIST &user : userlist)
    {
      if (user.name == payee)
      {
        user.balance += stoi(amount);
      }
    }
  }
}