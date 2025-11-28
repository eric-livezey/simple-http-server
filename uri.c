#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include "utils.h"
#include "hashmap.h"

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
    int32_t port;
    /// @brief The raw path component of this URI
    char *path;
    /// @brief The raw query component of this URI
    char *query;
};

/// @brief Initializes a hierarchical URI from the given components.
/// @param uri The URI
/// @param scheme Scheme name
/// @param user_info User name and authorization information
/// @param host Host name
/// @param port Port number
/// @param path Path
/// @param query Query
/// @param fragment Fragment
void URI_init_r(struct uri *uri, char *scheme, char *user_info, char *host, int port, char *path, char *query, char *fragment)
{
    uri->scheme = scheme;
    uri->user_info = user_info;
    uri->host = host;
    uri->port = port;
    uri->path = path;
    uri->query = query;
    uri->fragment = fragment;
}

/// @brief Initializes an empty hierarchical URI.
/// @param uri The URI
void URI_init(struct uri *uri)
{
    URI_init_r(uri, NULL, NULL, NULL, -1, NULL, NULL, NULL);
}

/// @brief Constructs a hierarchical URI from the given components.
/// @param scheme Scheme name
/// @param user_info User name and authorization information
/// @param host Host name
/// @param port Port number
/// @param path Path
/// @param query Query
/// @param fragment Fragment
/// @return The URI
struct uri *URI_new_r(char *scheme, char *user_info, char *host, int port, char *path, char *query, char *fragment)
{
    struct uri *uri = malloc(sizeof(struct uri));
    URI_init_r(uri, scheme, user_info, host, port, path, query, fragment);
    return uri;
}

/// @brief Constructs an empty hierarchical URI.
/// @return The URI
struct uri *URI_new()
{
    return URI_new_r(NULL, NULL, NULL, -1, NULL, NULL, NULL);
}

/// @brief Calculates the size of the string representation of the URI.
/// @param uri The URI
/// @return The size of the URI
int URI_size(struct uri *uri)
{
    // [<scheme>://][<user-info>@][<host>][:<port>][<path>][?<query>][#<fragment>]
    int len = 0;
    if (uri->scheme != NULL)
    {
        // <scheme>://
        len += strlen(uri->scheme) + 3;
    }
    if (uri->user_info != NULL)
    {
        // <user-info>@
        len += strlen(uri->user_info) + 1;
    }
    if (uri->host != NULL)
    {
        // <host>
        len += strlen(uri->host);
    }
    if (uri->port >= 0)
    {
        // :<port>
        len += numlenul(uri->port) + 1;
    }
    if (uri->path != NULL)
    {
        // <path>
        len += strlen(uri->path);
    }
    if (uri->query != NULL)
    {
        // ?<query>
        len += strlen(uri->query) + 1;
    }
    if (uri->fragment != NULL)
    {
        // #<fragment>
        len += strlen(uri->fragment) + 1;
    }
    return len + 1;
}

uint32_t URI_sprint(BUFFER *b, struct uri *uri)
{
    uint64_t initial_size = BUFFER_size(b);
    if (uri->scheme != NULL)
    {
        // <scheme>://
        BUFFER_sprintf(b, "%s://", uri->scheme);
    }
    if (uri->user_info != NULL)
    {
        // <user-info>@
        BUFFER_sprintf(b, "%s@", uri->user_info);
    }
    if (uri->host != NULL)
    {
        // <host>
        BUFFER_sprint(b, uri->host);
    }
    if (uri->port >= 0)
    {
        // :<port>
        BUFFER_sprintf(b, ":%d", uri->port);
    }
    if (uri->path != NULL)
    {
        // <path>
        BUFFER_sprint(b, uri->path);
    }
    if (uri->query != NULL)
    {
        // ?<query>
        BUFFER_sprintf(b, "?%s", uri->query);
    }
    if (uri->fragment != NULL)
    {
        // #<fragment>
        BUFFER_sprintf(b, "#%s", uri->fragment);
    }
    return BUFFER_size(b) - initial_size;
}

/// @brief Writes the string representation of the URI to the buffer.
/// @param uri The URI
/// @param buf The buffer
int URI_tostr_ex(struct uri *uri, char *buf)
{
    char *ep = buf;
    // [<scheme>://][<user-info>@][<host>][<path>][?<query>][#<fragment>]
    if (uri->scheme != NULL)
    {
        // <scheme>://
        ep += sprintf(ep, "%s://", uri->scheme);
    }
    if (uri->user_info != NULL)
    {
        // <user-info>@
        ep += sprintf(ep, "%s@", uri->user_info);
    }
    if (uri->host != NULL)
    {
        // <host>
        ep += sprintf(ep, "%s", uri->host);
    }
    if (uri->port >= 0)
    {
        // :<port>
        ep += sprintf(ep, ":%d", uri->port);
    }
    if (uri->path != NULL)
    {
        // <path>
        ep += sprintf(ep, "%s", uri->path);
    }
    if (uri->query != NULL)
    {
        // ?<query>
        ep += sprintf(ep, "?%s", uri->query);
    }
    if (uri->fragment != NULL)
    {
        // #<fragment>
        ep += sprintf(ep, "#%s", uri->fragment);
    }
    return ep - buf;
}

/// @brief Returns the string representation of the URI.
/// @param uri The URI
/// @return The string representation of the URI
char *URI_tostr(struct uri *uri)
{
    char *buf = malloc(URI_size(uri));
    URI_tostr_ex(uri, buf);
    return buf;
}

// Character-class masks, from RFC3986.

// DIGIT
static const uint64_t L_DIGIT = 0x3FF000000000000;
static const uint64_t H_DIGIT = 0x0;

// UPALPHA
static const uint64_t L_UPALPHA = 0x0;
static const uint64_t H_UPALPHA = 0x7FFFFFE;

// LOWALPHA
static const uint64_t L_LOWALPHA = 0x0;
static const uint64_t H_LOWALPHA = 0x7FFFFFE00000000;

// ALPHA
static const uint64_t L_ALPHA = L_LOWALPHA | L_UPALPHA;
static const uint64_t H_ALPHA = H_LOWALPHA | H_UPALPHA;

// ALPHA / DIGIT
static const uint64_t L_ALPHANUM = L_DIGIT | L_ALPHA;
static const uint64_t H_ALPHANUM = H_DIGIT | H_ALPHA;

// HEXDIG
static const uint64_t L_HEX = L_DIGIT;
static const uint64_t H_HEX = 0x7E0000007E;

// The zero'th bit is used to indicate that escape pairs are allowed
// this is handled by the scan_escape method below.
static const uint64_t L_ESCAPED = 0x1;
static const uint64_t H_ESCAPED = 0x1;

// sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
//               / "*" / "+" / "," / ";" / "="
static const uint64_t L_SUB_DELIMS = 0x28001FD200000000;
static const uint64_t H_SUB_DELIMS = 0x0;

// gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
static const uint64_t L_GEN_DELIMS = 0x8400800800000000;
static const uint64_t H_GEN_DELIMS = 0x28000001;

// reserved      = gen-delims / sub-delims
static const uint64_t L_RESERVED = L_SUB_DELIMS | L_GEN_DELIMS;
static const uint64_t H_RESERVED = H_SUB_DELIMS | H_GEN_DELIMS;

// unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
static const uint64_t L_UNRESERVED = L_ALPHANUM | 0x600000000000;
static const uint64_t H_UNRESERVED = H_ALPHANUM | 0x4000000080000000;

// pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
static const uint64_t L_PCHAR = L_UNRESERVED | L_ESCAPED | L_SUB_DELIMS | 0x400000000000000;
static const uint64_t H_PCHAR = H_UNRESERVED | H_ESCAPED | H_SUB_DELIMS | 0x1;

// query         = *( pchar / "/" / "?" )
static const uint64_t L_QUERY = L_PCHAR | 0x800800000000000;
static const uint64_t H_QUERY = H_PCHAR;

// fragment      = *( pchar / "/" / "?" )
static const uint64_t L_FRAGMENT = L_PCHAR | 0x800800000000000;
static const uint64_t H_FRAGMENT = H_PCHAR;

// userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
static const uint64_t L_USERINFO = L_UNRESERVED | L_ESCAPED | L_SUB_DELIMS | 0x400000000000000;
static const uint64_t H_USERINFO = H_UNRESERVED | H_ESCAPED | H_SUB_DELIMS;

// reg-name      = *( unreserved / pct-encoded / sub-delims )
static const uint64_t L_REG_NAME = L_UNRESERVED | L_ESCAPED | L_SUB_DELIMS;
static const uint64_t H_REG_NAME = H_UNRESERVED | H_ESCAPED | H_SUB_DELIMS;

// scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
static const uint64_t L_SCHEME = L_ALPHA | L_DIGIT | 0x680000000000;
static const uint64_t H_SCHEME = H_ALPHA | H_DIGIT;

/// @brief Scan a URL encoded escape sequence.
/// @param ptr Pointer
/// @param endptr End pointer
/// @return The length of the scanned sequence
int32_t scan_escape(char *ptr, char **endptr)
{
    char *ep = ptr;
    // Process escape pair
    if (*ep++ != '%' || !isxdigit(*ep++) || !isxdigit(*ep++))
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

/// @brief Scans all characters after the pointer that match the given mask.
/// @param ptr Pointer
/// @param endptr Optional end pointer
/// @param low_mask Low mask
/// @param high_mask High mask
/// @return The length of the partition of characters the pointer which matches the mask
uint32_t URI_scan(char *ptr, char **endptr, uint64_t low_mask, uint64_t high_mask)
{
    bool escaped = low_mask * L_ESCAPED != 0;
    low_mask &= ~L_ESCAPED;
    if (escaped)
    {
        return scan_r(ptr, endptr, &scan_escape, low_mask, high_mask);
    }
    return scan(ptr, endptr, low_mask, high_mask);
}

int scan_reg_name(char *ptr, char **endptr)
{
    return URI_scan(ptr, endptr, L_REG_NAME, H_REG_NAME);
}

// DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35 ; Any number from 0-255
int scan_dec_octet(char *ptr, char **endptr)
{
    char *ep = ptr;
    // Parse the integer until it's 3 digits long
    short n = 0;
    while (n < 100 && isdigit(*ep))
    {
        n = n * 10 + *(ep++) - '0';
    }
    if (n > 255)
    {
        // The number is greater than 255, so omit the last character
        ep--;
    }
    if (ptr == ep)
    {
        // The string is empty, so return null
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// dec-octet "." dec-octet "." dec-octet "." dec-octet
int scan_ipv4_address(char *ptr, char **endptr)
{
    char *ep = ptr;
    // dec-octet
    if (scan_dec_octet(ep, &ep) < 0)
        return -1;
    for (char i = 0; i < 3; i++)
    {
        // "."
        if (*ep != '.')
        {
            return -1;
        }
        ep++;
        // dec-octet
        if (scan_dec_octet(ep, &ep) < 0)
        {
            return -1;
        }
    }
    if (endptr != NULL)
        *endptr = ep;
    return ep - ptr;
}

// IPv6address   =                            6( h16 ":" ) ls32
//               /                       "::" 5( h16 ":" ) ls32
//               / [               h16 ] "::" 4( h16 ":" ) ls32
//               / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
//               / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
//               / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
//               / [ *4( h16 ":" ) h16 ] "::"              ls32
//               / [ *5( h16 ":" ) h16 ] "::"              h16
//               / [ *6( h16 ":" ) h16 ] "::"
int scan_ipv6_address(char *ptr, char **endptr)
{
    // The unusually long abnf is just to account for the short form
    // :: is valid
    // FFFF::FF is valid
    // ::FFFF::FFFF is ambigous so invalid
    // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF is valid
    // FF::FFFF:FFFF:FFFF:FFFF:255.255.255.255 is valid
    // Essentially up to 8 segments with no more than one short form
    // Then the last two segments can be an ipv4
    char *ep = ptr, n = 0;
    bool short_form = false, seg = true;
    while (n < 8)
    {
        if (seg && (n == 6 || short_form && n < 6) && scan_ipv4_address(ep, &ep) >= 0)
        {
            // Pointer is a terminating IPv4 address, so count 2 segments and break
            n += 2;
            break;
        }
        else if (seg && scann(ep, &ep, 4, L_HEX, H_HEX) > 0)
        {
            // Character is a hex digit
            seg = false;
            n++;
        }
        else if (n == 0 && *ep == ':')
        {
            // Character is ":" and is the first character, so scan the short form
            ep++;
            if (*ep != ':')
            {
                return -1;
            }
            ep++;
            n++;
            short_form = true;
        }
        else if (!seg && *ep == ':')
        {
            // Character is ":", so scan the separator or short form
            seg = true;
            ep++;
            if (!short_form && *ep == ':')
            {
                // Next character is ":" and no short form has been scanned, so scan the short form
                ep++;
                n++;
                short_form = true;
            }
        }
        else
        {
            // Pointer is not a valid token, so break
            break;
        }
    }
    if (n != 8 && (!short_form || n > 8))
    {
        // There must be either 8 segments or the short form and less than 8 segments
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
int scan_ipvfuture(char *ptr, char **endptr)
{
    char *ep = ptr;
    // "v"
    if (*ep != 'v')
    {
        return -1;
    }
    ep++;
    // 1*HEXDIG
    if (URI_scan(ep, &ep, L_HEX, H_HEX) < 1)
    {
        return -1;
    }
    // "."
    if (*ep != '.')
    {
        return -1;
    }
    ep++;
    // 1*( unreserved / sub-delims / ":" )
    if (URI_scan(ep, &ep, L_USERINFO, H_USERINFO) < 1)
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// "[" ( IPv6address / IPvFuture ) "]"
int scan_ip_literal(char *ptr, char **endptr)
{
    char *ep = ptr;
    // "["
    if (*ep != '[')
    {
        return -1;
    }
    ep++;
    // ( IPv6address / IPvFuture )
    if (scan_ipv6_address(ep, &ep) < 0 && scan_ipvfuture(ep, &ep) < 0)
    {
        return -1;
    }
    // "]"
    if (*ep != ']')
    {
        return -1;
    }
    ep++;
    set_endptr(endptr, ep);
    return ep - ptr;
}

int scan_query(char *ptr, char **endptr)
{
    char *ep = ptr;
    // "?"
    if (*ep != '?')
    {
        return -1;
    }
    ep++;
    URI_scan(ep, &ep, L_QUERY, H_QUERY);
    set_endptr(endptr, ep);
    return ep - ptr;
}

int scan_fragment(char *ptr, char **endptr)
{
    char *ep = ptr;
    // "#"
    if (*ep != '#')
    {
        return -1;
    }
    ep++;
    URI_scan(ep, &ep, L_FRAGMENT, H_FRAGMENT);
    set_endptr(endptr, ep);
    return ep - ptr;
}

// *( "/" segment )
int scan_path_abempty(char *ptr, char **endptr)
{
    char *ep = ptr;
    // *( "/" segment )
    while (*ep == '/')
    {
        ep++;
        URI_scan(ep, &ep, L_PCHAR, H_PCHAR);
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// segment-nz *( "/" segment )
int scan_path_rootless(char *ptr, char **endptr)
{
    char *ep = ptr;
    if (URI_scan(ep, &ep, L_PCHAR, H_PCHAR) < 1)
    {
        return -1;
    }
    // *( "/" segment )
    if (scan_path_abempty(ep, &ep) < 0)
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// path-absolute  = "/" [ segment-nz *( "/" segment ) ]
int scan_path_absolute(char *ptr, char **endptr)
{
    char *ep = ptr;
    // "/"
    if (*ep != '/')
    {
        return -1;
    }
    ep++;
    // [ segment-nz *( "/" segment ) ]
    scan_path_rootless(ep, &ep);
    set_endptr(endptr, ep);
    return ep - ptr;
}

// host           = IP-literal / IPv4address / reg-name
int scan_host(char *ptr, char **endptr)
{
    char *ep = ptr;
    if (scan_ip_literal(ep, &ep) < 0 && scan_ipv4_address(ep, &ep) < 0 && scan_reg_name(ep, &ep) < 0)
    {
        return -1;
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// authority      = [ userinfo "@" ] host [ ":" port ]
int parse_authority(char *ptr, char **endptr, struct uri *uri)
{
    char *p = ptr, *ep = ptr;
    // userinfo
    URI_scan(ep, &ep, L_USERINFO, H_USERINFO);
    // "@"
    if (*ep == '@')
    {
        *ep = '\0';
        ep++;
        uri->user_info = p;
    }
    else
    {
        ep = p;
    }
    p = ep;
    // host
    if (scan_host(ep, &ep) < 0)
    {
        return -1;
    }
    uri->host = p;
    // ":" port
    if (*ep == ':')
    {
        *ep = '\0';
        ep++;
        // *DIGIT
        uri->port = strtoi(ep, &ep, 10);
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}

// absolute-URI   = scheme ":" hier-part [ "?" query ]
// scheme         = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
// hier-part      = "//" authority path-abempty
//                / path-absolute
//                / path-rootless
//                / path-empty
int parse_absolute_URI(char *ptr, char **endptr, struct uri *uri, STACK *stack)
{
    char *p = ptr, *ep = ptr, *src;
    int n;
    // ALPHA
    if (!isalpha(*ep))
    {
        return -1;
    }
    ep++;
    // scheme
    if (URI_scan(ep, &ep, L_SCHEME, H_SCHEME) < 0)
    {
        return -1;
    }
    uri->scheme = p;
    // ":"
    if (*ep != ':')
    {
        return -1;
    }
    *ep = '\0';
    ep++;
    p = ep;
    // "//" authority path-abempty / path-absolute / path-rootless / path-empty
    if (strncmp(ep, "//", 2) != 0 || parse_authority(ep + 2, &ep, uri) < 0 || (n = scan_path_abempty(src = ep, &ep)) < 0)
    {
        uri->user_info = NULL;
        ep = p;
        if (scan_path_absolute(ep, &ep) < 0)
            scan_path_rootless(ep, &ep);
        // path-empty is empty so the path is still valid even if nothing else matches
        uri->path = p;
    }
    else
    {
        // allocate memory for the path to allow a leading "/"
        uri->path = strnalloc(src, n, stack);
        if (n > 0)
        {
            *src = '\0';
        }
    }
    p = ep;
    // [ "?" query ]
    if ((n = scan_query(src = ep, &ep)) >= 0)
    {
        // allocate memory for the query to allow the leading "?"
        uri->query = strnalloc(src, n, stack);
        if (n > 0)
        {
            *src = '\0';
        }
    }
    set_endptr(endptr, ep);
    return ep - ptr;
}
