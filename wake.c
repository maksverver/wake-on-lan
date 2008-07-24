#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int verbose;
static int count;
static struct sockaddr *target_addr;    /* Initialized by parse_host() */
static int target_addr_len;             /* Initialized by parse_host() */
static char target_mac[6];              /* Initialized by parse_mac() */
static char magic_packet[102];          /* Initialized by parse_mac() */

static void parse_host(const char *arg)
{
    struct addrinfo hints, *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = PF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(arg, "discard", &hints, &result) != 0 || !result)
    {
        fprintf(stderr, "Could not determine address of host \"%s\"!\n", arg);
        exit(1);
    }

    target_addr_len = result->ai_addrlen;
    target_addr = malloc(target_addr_len);
    if (target_addr == NULL)
    {
        fprintf(stderr, "Memory allocation failed!\n");
        exit(1);
    }
    memcpy(target_addr, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
}

static void parse_mac(const char *arg)
{
    static const char *hexdigits = "0123456789ABCDEF";
    char buf[12];
    const char *p;
    int pos = 0;

    for (p = arg; *p != '\0'; ++p)
        if (isxdigit(*p))
        {
            if (pos == 12)
                break;
            buf[pos++] = toupper(*p);
        }
    if (pos != 12 || *p != '\0')
    {
        fprintf(stderr, "Invalid MAC address: \"%s\"!\n", arg);
        exit(1);
    }

    /* Convert to bytes */
    for (pos = 0; pos < 6; ++pos)
    {
        ((unsigned char*)target_mac)[pos] =
            16*(strchr(hexdigits, buf[2*pos + 0]) - hexdigits) +
                strchr(hexdigits, buf[2*pos + 1]) - hexdigits;
    }

    /* Create magic packet */
    for (pos = 0; pos < 102; ++pos)
        magic_packet[pos] = pos < 6 ? (char)-1 : target_mac[pos%6];
}

static void usage()
{
    printf( "Usage: wake [-v] [-c count] [-h host] <mac>\n\n"
"    -v          Verbose output.\n\n"
"    -c count    Send ``count'' packets with a one second interval (default: 1)\n\n"
"    -h host     Target hostname or IP address (default: IPv4 broadcast).\n\n"
"    mac         Ethernet (MAC) address in 12 hexadecimal digits; other\n"
"                characters (such as grouping characters) are ignored.\n\n" );
    exit(0);
}

static void parse_args(int argc, char *argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "vc:h:")) != -1)
    {
        switch (opt)
        {
        case 'v':
            if (verbose)
            {
                printf("Duplicate option: -v\n\n");
                exit(1);
            }
            verbose = 1;
            break;

        case 'c':
            if (count)
            {
                printf("Duplicate option: -c\n\n");
                exit(1);
            }
            count = atoi(optarg);
            if (count <= 0)
            {
                printf("Invalid argument to -c: %s\n\n", optarg);
                exit(1);
            }
            break;

        case 'h':
            if (target_addr)
            {
                printf("Duplicate option: -h\n\n");
                exit(1);
            }
            parse_host(optarg);
            break;

        default:
            printf("Unrecognized option: -%c\n\n", (char)opt);
            exit(1);
        }
    }

    if (optind < argc - 1)
    {
        printf("Too many arguments.\n\n");
        exit(1);
    }

    if (optind > argc - 1)
    {
        usage();
        exit(0);
    }

    parse_mac(argv[argc - 1]);
}

int main(int argc, char *argv[])
{
    int s, n;

    parse_args(argc, argv);

    /* Set default count */
    if (!count)
        count = 1;

    /* Create datagram socket */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        perror("socket() failed");
        exit(1);
    }

    /* Enable broadcasting -- may not always be possible! */
    {
        int broadcast = 1;
        if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)))
            perror("Warning: setsockopt(SO_BROADCAST) failed");
    }

    if (!target_addr) 
    {
        struct in_addr addr;
        addr.s_addr = htonl(INADDR_BROADCAST);
        parse_host(inet_ntoa(addr));
    }

    /* Send magic packets */
    for (n = 1; n <= count; ++n)
    {
        if (verbose)
        {
            printf("Sending packet %d of %d... ", n, count);
            fflush(stdout);
        }

        if (sendto(s, magic_packet, sizeof(magic_packet), 0,
            target_addr, target_addr_len) != sizeof(magic_packet))
        {
            perror("sendto() failed");
            exit(1);
        }

        if (verbose)
        {
            printf("done.\n");
            fflush(stdout);
        }

        if (n < count)
            sleep(1);
    }

    return 0;
}
