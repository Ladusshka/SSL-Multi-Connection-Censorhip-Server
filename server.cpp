#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <set>
#include <map>
#include <string>
#include <thread>

struct Client {
    SSL *ssl;
    std::set<std::string> censored_words;
    std::string message_buffer;
    bool reading_censorship;

    Client(SSL *ssl_connection) : ssl(ssl_connection), reading_censorship(true) {}
};

class SSLServer {
private:
    SSL_CTX *ssl_ctx;
    int server_fd;

    void censor(const std::set<std::string> &censored_words, std::string &message) {
        for (const auto &word : censored_words) {
            size_t pos = 0;
            while ((pos = message.find(word, pos)) != std::string::npos) {
                message.replace(pos, word.length(), std::string(word.length(), '-'));
                pos += word.length();
            }
        }
    }

    void handle_client(Client client) {
        char buffer[1000];
        ssize_t bytes_received=0;
        std::string word;
        ssize_t index = -1;

        while (client.reading_censorship) {
            bytes_received = SSL_read(client.ssl, buffer, sizeof(buffer));
            if (bytes_received <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }

            for (ssize_t i = 0; i < bytes_received; i++) {
                if (buffer[i] == 0x1F) {
                    client.reading_censorship = false;
                    client.censored_words.insert(word);
                    word.clear();
                    index = i;
                    break;
                } else if (buffer[i] == 0x1E) {
                    client.censored_words.insert(word);
                    word.clear();
                } else {
                    word.push_back(buffer[i]);
                }
            }
        }

        bool end = false;

        if (bytes_received > 0) {
            for(ssize_t j = index + 1; j < bytes_received; j++){
                client.message_buffer.push_back(buffer[j]);

                if(buffer[j] == 0x1F){
                    end = true;
                    censor(client.censored_words, client.message_buffer);
                    SSL_write(client.ssl, client.message_buffer.c_str(), client.message_buffer.length());
                    client.message_buffer.clear();
                    break;
                }else if(buffer[j] == 0x1E){

                    censor(client.censored_words, client.message_buffer);
                    SSL_write(client.ssl, client.message_buffer.c_str(), client.message_buffer.length());
                    client.message_buffer.clear();

                }
            }
        }

        while (!end) {
            bytes_received = SSL_read(client.ssl, buffer, sizeof(buffer));
            if (bytes_received <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }

            for (ssize_t i = 0; i < bytes_received; i++) {
                client.message_buffer.push_back(buffer[i]);

                if (buffer[i] == 0x1F) {
                    end = true;
                    censor(client.censored_words, client.message_buffer);
                    SSL_write(client.ssl, client.message_buffer.c_str(), client.message_buffer.length());
                    client.message_buffer.clear();
                    break;
                } else if (buffer[i] == 0x1E) {
                    censor(client.censored_words, client.message_buffer);
                    SSL_write(client.ssl, client.message_buffer.c_str(), client.message_buffer.length());
                    client.message_buffer.clear();
                }
            }
        }

        SSL_shutdown(client.ssl);
        SSL_free(client.ssl);
    }

public:
    SSLServer() : ssl_ctx(nullptr), server_fd(-1) {}

    ~SSLServer() {
        if (server_fd >= 0) close(server_fd);
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    }

    void init_ssl(const std::string &cert_file, const std::string &key_file, const std::string &ca_file) {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();

        const SSL_METHOD *method = TLS_server_method();
        ssl_ctx = SSL_CTX_new(method);
        if (!ssl_ctx) {
            throw std::runtime_error("Unable to create SSL context");
        }

        if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Failed to load certificate");
        }

        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Failed to load private key");
        }

        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            throw std::runtime_error("Private key does not match the certificate public key");
        }

        if (!SSL_CTX_load_verify_locations(ssl_ctx, ca_file.c_str(), nullptr)) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Failed to load CA file");
        }

        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, nullptr);
    }

    void create_socket(int port) {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            throw std::runtime_error("Failed to bind socket");
        }

        if (listen(server_fd, 10) < 0) {
            throw std::runtime_error("Failed to listen on socket");
        }

        std::cout << "Server listening on port " << port << "..." << std::endl;
    }

    void run() {
        while (true) {
            sockaddr_in client_addr;
            socklen_t len = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &len);

            if (client_fd < 0) {
                std::cerr << "Failed to accept client" << std::endl;
                continue;
            }

            SSL *ssl = SSL_new(ssl_ctx);
            SSL_set_fd(ssl, client_fd);

            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                close(client_fd);
                SSL_free(ssl);
                continue;
            }

            Client client(ssl);
            std::thread(&SSLServer::handle_client, this, std::move(client)).detach();
        }
    }
};

int main() {
    try {
        SSLServer server;
        server.init_ssl("server.crt", "server.key", "rootCA.crt");
        server.create_socket(1337);
        server.run();
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
