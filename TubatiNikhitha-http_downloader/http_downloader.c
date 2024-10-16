#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define PORT "443"
#define URL_LENGTH 200

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

struct URLInfo {
    struct addrinfo *server_addr_prurl;
    char host[INET6_ADDRSTRLEN];
    char server_url[URL_LENGTH];
    char out_filename[200];
    char path[URL_LENGTH];
    int r_start;
    int r_end;
    int range;
};

void cleanup_openssl() {
    EVP_cleanup();
}

void parseAndresolveURL(struct URLInfo *prurl, char *url) {
    struct addrinfo hints, *result;
    char *http_start = strstr(url, "://");
    if (http_start == NULL) {
	 fprintf(stderr, "Invalid URL format\n");
        exit(-1);
    }
    http_start += 3;
    char *slash_start = strchr(http_start, '/');
    if (slash_start == NULL) {
        fprintf(stderr, "Invalid URL format\n");
        exit(-1);
    }
    strcpy(prurl->path, slash_start);
    char dupl_url[URL_LENGTH];
    strcpy(dupl_url, url);
    char *ptr = strtok(dupl_url, "//");
    int i = 0;
    while (i < 1) {
        ptr = strtok(NULL, "//");
        i += 1;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int s = getaddrinfo(ptr, PORT, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(-1);
    }
    prurl->server_addr_prurl = result;
    size_t host_len = slash_start - http_start;
    strncpy(prurl->host, http_start, host_len);
    prurl->host[host_len] = '\0';
}

int get_file_size(struct URLInfo *prurl) {
    struct addrinfo *result = prurl->server_addr_prurl;
    char *ip = prurl->host;
    char *file_path = prurl->path;
    int file_size = 0;
    int sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock < 0) {
        fprintf(stderr, "Socket connection failed\n");
        exit(1);
    }
    if (connect(sock, result->ai_addr, result->ai_addrlen) != 0) {
        fprintf(stderr, "Connection failed\n");
        close(sock);
        exit(1);
    }
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Unable to create SSL context\n");
        close(sock);
        return -1;
    }
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        fprintf(stderr, "Unable to create SSL object\n");
        SSL_CTX_free(ssl_ctx);
        close(sock);
        return -1;
    }
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        close(sock);
        return -1;
    }
    char http_query[1024];
    sprintf(http_query, "HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", file_path, ip);
    SSL_write(ssl, http_query, strlen(http_query));
    char http_response[2000];
    SSL_read(ssl, http_response, sizeof(http_response));
    char *match = strstr(http_response, "Content-Length");
    if (match) {
        match = strtok(match, "\r\n");
        strtok(match, " ");
        file_size = atoi(strtok(NULL, " "));
    } else {
        fprintf(stderr, "Unable to determine file size\n");
    }
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sock);
    return file_size;
}

void *create_tls_session(void *serv_prurl) {
    struct URLInfo *prurl = (struct URLInfo *)serv_prurl;
    struct addrinfo *server = prurl->server_addr_prurl;
    char *ip = prurl->host;
    char *file_path = prurl->path;
    int r_start = prurl->r_start;
    int r_end = prurl->r_end;
    int range = prurl->range;
    int sock = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
    if (sock < 0) {
        fprintf(stderr, "Socket connection failed in thread\n");
        pthread_exit(NULL);
    }

    if (connect(sock, server->ai_addr, server->ai_addrlen) != 0) {
        fprintf(stderr, "Connection failed in thread\n");
        close(sock);
        pthread_exit(NULL);
    }

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context in thread\n");
        close(sock);
        pthread_exit(NULL);
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Unable to create SSL object in thread\n");
        SSL_CTX_free(ctx);
        close(sock);
        pthread_exit(NULL);
    }

    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
	SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        pthread_exit(NULL);
    }

    // Send the GET request with the Range header
    char http_query[1024];
    sprintf(http_query, "GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%d-%d\r\nConnection: close\r\n\r\n", file_path, ip, r_start, r_end);
    SSL_write(ssl, http_query, strlen(http_query));

    char filename[100];
    sprintf(filename, "part_%d", range); // Save each chunk to a separate file
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file %s in thread\n", filename);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        pthread_exit(NULL);
    }

    char buffer[8192];
    int bytes;
    int header_end = 0; // Flag to track if we have skipped the HTTP headers
    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        // Find the end of the HTTP headers (look for \r\n\r\n)
        if (!header_end) {
            char *header_end_ptr = strstr(buffer, "\r\n\r\n");
            if (header_end_ptr) {
                header_end = 1;
                // Write only the content after the headers
                fwrite(header_end_ptr + 4, 1, bytes - (header_end_ptr + 4 - buffer), file);
            }
        } else {
            // Write the content normally once headers are skipped
	    fwrite(buffer, 1, bytes, file);
        }
    }

    fclose(file);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    pthread_exit(NULL);
}

void merge_files(const char *output_file, int num_of_threads) {
    FILE *out = fopen(output_file, "wb");
    if (!out) {
        fprintf(stderr, "Failed to open output file %s for merging\n", output_file);
        return;
    }
    char filename[100];
    for (int i = 0; i < num_of_threads; i++) {
        sprintf(filename, "part_%d", i);
        printf("Merging file: %s\n", filename); // Debug print
        FILE *in = fopen(filename, "rb");
        if (in) {
            char buffer[8192];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), in)) > 0) {
                fwrite(buffer, 1, bytes, out);
            }
            fclose(in);
        } else {
            fprintf(stderr, "Warning: Could not open file %s for merging\n", filename);
        }
    }
    fclose(out);
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s -u <url> -n <num_chunks> -o <output_file>\n", argv[0]);
        exit(1);
    }
    char *url = NULL;
    int num_of_threads = 0;
    char *output_file = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-u") == 0) {
            url = argv[i + 1];
        } else if (strcmp(argv[i], "-n") == 0) {
            num_of_threads = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "-o") == 0) {
            output_file = argv[i + 1];
        }
    }
    if (!url || num_of_threads <= 0 || !output_file) {
        fprintf(stderr, "Invalid arguments\n");
        return -1;
    }
    init_openssl();
    struct URLInfo server_prurl;
    parseAndresolveURL(&server_prurl, url);
    int file_size = get_file_size(&server_prurl);
    if (file_size < 0) {
        fprintf(stderr, "Failed to get file size\n");
        return -1;
    }
    pthread_t *threads = malloc(num_of_threads * sizeof(pthread_t));
    struct URLInfo *url_ptr = malloc(num_of_threads * sizeof(struct URLInfo));
    int chunk_size = file_size / num_of_threads;
    for (int i = 0; i < num_of_threads; i++) {
        url_ptr[i] = server_prurl;
        url_ptr[i].r_start = i * chunk_size;
        if (i == num_of_threads - 1) {
            url_ptr[i].r_end = file_size - 1;
        } else {
	    url_ptr[i].r_end = (i + 1) * chunk_size - 1;
        }
        url_ptr[i].range = i;
        pthread_create(&threads[i], NULL, create_tls_session, (void *)&url_ptr[i]);
    }
    for (int i = 0; i < num_of_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    merge_files(output_file, num_of_threads);
    free(threads);
    free(url_ptr);
    cleanup_openssl();
    return 0;
}
