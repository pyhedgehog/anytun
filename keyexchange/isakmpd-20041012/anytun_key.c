#include "anytun_key.h"
#include "pf_key_v2.h"
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <string.h>
#include "sysdep.h"

#include "cert.h"
#include "conf.h"
#include "exchange.h"
#include "ipsec.h"
#include "ipsec_num.h"
#include "key.h"
#include "log.h"
#include "pf_key_v2.h"
#include "sa.h"
#include "timer.h"
#include "transport.h"
#include "util.h"

#include <sys/socket.h>
#include <netdb.h>
#include "pf_key_v2.c"

int	anytun_key_socket;

void     anytun_key_connection_check(char * conn)
{
	pf_key_v2_connection_check(conn);
}

int      anytun_key_delete_spi(struct sa *sa, struct proto *proto, int incoming)
{
return pf_key_v2_delete_spi(sa, proto, incoming);
}

int      anytun_key_enable_sa(struct sa *sa, struct sa *isakmp_sa)
{
  struct ipsec_sa *isa = sa->data;
  struct sockaddr *dst, *src;
	char            idsrc[256], iddst[256];
//  int             error;
//  struct proto   *proto = TAILQ_FIRST(&sa->protos);
//  int             sidtype = 0, didtype = 0;
//  size_t          sidlen = 0, didlen = 0;
//  u_int8_t       *sid = 0, *did = 0;

  sa->transport->vtbl->get_dst(sa->transport, &dst);
  sa->transport->vtbl->get_src(sa->transport, &src);
  if (getnameinfo(src, sysdep_sa_len(src), idsrc, sizeof idsrc, NULL, 0,
      NI_NUMERICHOST) != 0) {
    log_print("udp_decode_ids: getnameinfo () failed for 'src'");
    strlcpy(idsrc, "<error>", 256);
  }
  if (getnameinfo(dst, sysdep_sa_len(dst), iddst, sizeof iddst, NULL, 0,
      NI_NUMERICHOST) != 0) {
    log_print("udp_decode_ids: getnameinfo () failed for 'dst'");
    strlcpy(iddst, "<error>", 256);
  }

	printf( "anytun src: %s dst: %s\n", idsrc, iddst);

//struct ipsec_sa {
//  /* Phase 1.  */
//  u_int8_t        hash;
//  size_t          skeyid_len;
//  u_int8_t       *skeyid_d;
//  u_int8_t       *skeyid_a;
//  u_int16_t       prf_type;
//
//  /* Phase 2.  */
//  u_int16_t       group_desc;
//
//  /* Tunnel parameters.  These are in network byte order.  */
//  struct sockaddr *src_net;
//  struct sockaddr *src_mask;
//  struct sockaddr *dst_net;
//  struct sockaddr *dst_mask;
//  u_int8_t        tproto;
//  u_int16_t       sport;
//  u_int16_t       dport;
//};


return pf_key_v2_enable_sa(sa, isakmp_sa);
}

//int	anytun_key_enable_spi(in_addr_t, in_addr_t, in_addr_t,
//    in_addr_t, u_int8_t *, u_int8_t, in_addr_t)
//		{
//		}

struct sa_kinfo * anytun_key_get_kernel_sa(u_int8_t *spi, size_t spi_sz, u_int8_t proto,
    struct sockaddr *dst)
{
		return pf_key_v2_get_kernel_sa(spi, spi_sz, proto,
		    dst);
}

u_int8_t *anytun_key_get_spi(size_t *sz, u_int8_t proto, struct sockaddr *src,
          struct sockaddr *dst, u_int32_t seq)
		{
      //*sz = 4;
      /* XXX should be random instead I think.  */
      //return strdup ("\x12\x34\x56\x78");
			return pf_key_v2_get_spi(sz,  proto, src,
			          dst, seq);
		}

int	anytun_key_group_spis(struct sa *sa, struct proto *proto1,
         struct proto *proto2, int incoming)
		{
return pf_key_v2_group_spis(sa, proto1,
         proto2, incoming);
		}

void     anytun_key_handler(int fd)
{
	pf_key_v2_handler(fd);
}

int      anytun_key_open(void)
{
return pf_key_v2_open();
}

int      anytun_key_set_spi(struct sa *sa, struct proto *proto, int incoming,
    struct sa *isakmp_sa)
	 {
return pf_key_v2_set_spi(sa, proto, incoming,
    isakmp_sa);
	 }


