#include "anytun_key.h"
#include <sys/types.h>

struct proto;
struct sa;
struct sockaddr;
struct kernel_sa;

int	anytun_key_socket;

void     anytun_key_connection_check(char * conn)
{
}

int      anytun_key_delete_spi(struct sa *sa, struct proto *proto, int incoming)
{
}

int      anytun_key_enable_sa(struct sa *sa, struct sa *isakmp_sa)
{
}

//int	anytun_key_enable_spi(in_addr_t, in_addr_t, in_addr_t,
//    in_addr_t, u_int8_t *, u_int8_t, in_addr_t)
//		{
//		}

struct sa_kinfo * anytun_key_get_kernel_sa(u_int8_t *spi, size_t spi_sz, u_int8_t proto,
    struct sockaddr *dst)
{
		return 0;
}

u_int8_t *anytun_key_get_spi(ze_t *sz, u_int8_t proto, struct sockaddr *src,
    struct sockaddr *dst, u_int32_t seq)
		{
		}

int	anytun_key_group_spis(struct sa *sa, struct proto *proto1,
         struct proto *proto2, int incoming)
		{
		}

void     anytun_key_handler(int fd)
{
}

int      anytun_key_open(void)
{
}

int      anytun_key_set_spi(struct sa *sa, struct proto *proto, int incoming,
    struct sa *isakmp_sa)
	 {
	 }


