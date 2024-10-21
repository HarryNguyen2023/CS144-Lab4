
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#define UNSOLICITED_INBOUND_TIMEOUT 6

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

/*
 * Flag to indicate the direction of the packet
 */
typedef enum {
  nat_inbound,
  nat_outbound
} sr_nat_direction;

/*
 * Flag to indicate the state of the TCP connection
*/
typedef enum {
  nat_icmp,
  nat_tcp_unsolicited_inbound_start,
  nat_tcp_syn_1,
  nat_tcp_syn_2,
  nat_tcp_established,
  nat_tcp_fin_1,
  nat_tcp_fin_2,
  nat_tcp_full_close
} sr_nat_tcp_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  sr_nat_tcp_state tcp_state;

  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  uint8_t valid;
  uint8_t icmp_query_timeout;
  uint16_t tcp_est_idle_timeout;
  uint16_t tcp_trans_idle_timeout;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat, uint8_t icmp_query_timeout, 
                  uint16_t tcp_estab_idle_timeout, uint16_t tcp_transit_idle_timeout);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat, 
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, sr_nat_tcp_state conn_state );

int sr_nat_handle(struct sr_nat *nat, uint8_t *ip_datagram, uint16_t len, sr_nat_direction nat_dir);

#endif