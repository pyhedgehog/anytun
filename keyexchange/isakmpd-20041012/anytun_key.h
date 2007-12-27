#ifndef _ANYTUN_KEY_H_
#define _ANYTUN_KEY_H_

#include <sys/types.h>
#include <sys/queue.h>

struct proto;
struct sa;
struct sockaddr;
struct kernel_sa;

extern int	anytun_key_socket;

extern void     anytun_key_connection_check(char *);
extern int      anytun_key_delete_spi(struct sa *, struct proto *, int);
extern int      anytun_key_enable_sa(struct sa *, struct sa *);
//extern int	anytun_key_enable_spi(in_addr_t, in_addr_t, in_addr_t,
//    in_addr_t, u_int8_t *, u_int8_t, in_addr_t);
extern struct sa_kinfo *anytun_key_get_kernel_sa(u_int8_t *, size_t, u_int8_t, struct sockaddr *);
extern u_int8_t *anytun_key_get_spi(size_t *sz, u_int8_t proto, struct sockaddr *src,
          struct sockaddr *dst, u_int32_t seq);
extern int	anytun_key_group_spis(struct sa *, struct proto *,
    struct proto *, int);
extern void     anytun_key_handler(int);
extern int      anytun_key_open(void);
extern int      anytun_key_set_spi(struct sa *, struct proto *, int,
    struct sa *);

#endif				/* _ANYTUN_KEY_H_ */
