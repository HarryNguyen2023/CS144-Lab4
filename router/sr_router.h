/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_nat.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    struct sr_nat nat;   /* NAT module */
    pthread_attr_t attr;
    FILE* logfile;
};

/*
 * The flag for types of Ethernet packet
*/
typedef enum 
{
  ETH_NO_MSG,
  ETHER_ARP_REQ,
  ETHER_ARP_REP,
  ETHER_IP_TO_US_ICMP,
  ETHER_IP_TO_US_TRACEROUTE,
  ETHER_IP_TO_ELSE
}ETHER_TYPE;

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

void sr_icmp_t3_create(sr_icmp_t3_hdr_t * icmp_t3_segment, uint8_t *ip_datagram, uint8_t icmp_type, uint8_t icmp_code);
void sr_icmp_t0_create(sr_icmp_t0_hdr_t * icmp_t0_segment, uint8_t *rcv_icmp_t0_segment, uint16_t len, uint8_t icmp_type, uint8_t icmp_code);
void sr_ip_create(sr_ip_datagram *ip_datagram, uint8_t *data, uint16_t len, uint8_t protocol, uint32_t src_ip_addr, uint32_t dest_ip_addr);
void sr_ethernet_create(sr_ethernet_packet *ethernet_packet, uint8_t *data, uint16_t len, uint8_t *src_mac_addr, uint8_t *dest_mac_addr, enum sr_ethertype type);
void sr_icmp_send(struct sr_instance *sr, uint8_t *dest_mac_addr, uint8_t *ip_datagram, uint16_t len, uint8_t icmp_type, uint8_t icmp_code, char *iface);

#endif /* SR_ROUTER_H */
