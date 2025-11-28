#include "utils.h"

/// @brief Represents a Uniform Resource Identifier (URI) reference.
struct uri
{
    /// @brief The scheme component of this URI.
    char *scheme;
    /// @brief The raw fragment component of this URI.
    char *fragment;
    /// @brief The raw user-information component of this URI.
    char *user_info;
    /// @brief The host component of this URI.
    char *host;
    /// @brief The port number of this URI.
    int port;
    /// @brief The raw path component of this URI
    char *path;
    /// @brief The raw query component of this URI
    char *query;
};

void URI_init_r(struct uri *uri, char *scheme, char *user_info, char *host, int port, char *path, char *query, char *fragment);

void URI_init(struct uri *uri);

struct uri *URI_new_r(char *scheme, char *user_info, char *host, int port, char *path, char *query, char *fragment);

struct uri *URI_new();

int URI_size(struct uri *uri);

uint32_t URI_sprint(BUFFER *b, struct uri *uri);

int URI_tostr_ex(struct uri *uri, char *buf);

char *URI_tostr(struct uri *uri);

char *URI_tostr(struct uri *uri);

int scan_dec_octet(char *ptr, char **endptr);

int scan_ipv4_address(char *ptr, char **endptr);

int scan_ipv6_address(char *ptr, char **endptr);

int scan_ipvfuture(char *ptr, char **endptr);

int scan_ip_literal(char *ptr, char **endptr);

int scan_query(char *ptr, char **endptr);

int scan_fragment(char *ptr, char **endptr);

int scan_reg_name(char *ptr, char **endptr);

int scan_path_abempty(char *ptr, char **endptr);

int scan_path_rootless(char *ptr, char **endptr);

int scan_path_absolute(char *ptr, char **endptr);

int parse_authority(char *ptr, char **endptr, struct uri *uri);

int parse_absolute_URI(char *ptr, char **endptr, struct uri *uri, STACK *stack);
