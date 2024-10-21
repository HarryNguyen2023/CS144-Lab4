/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

#define IP_MIN_LEN  46

/************************* Private function prototypes **************************/
static void sr_icmp_req_handle(struct sr_instance *sr, uint8_t *dest_mac_addr, uint8_t *ip_datagram, uint16_t len, char *iface);
static void sr_arp_rep_create(sr_arp_hdr_t *rep_arp_datagram, sr_arp_hdr_t* arp_req_datagram, uint8_t* target_mac_addr);
static void sr_arp_req_handle(struct sr_instance *sr, sr_arp_hdr_t *req_arp_hdr, char *iface);
static struct sr_rt *sr_get_forward_interface(struct sr_instance *sr, uint32_t target_ip_addr, char *rcv_iface);
static void sr_forward_handle(struct sr_instance *sr, uint8_t *dest_mac_addr, uint8_t *ip_datagram, uint16_t len, char *iface);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Elimintae too short Ethernet packet */
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
  {
    printf( "Error: Ethernet packet too short!\n");
    return;
  }
  ETHER_TYPE eth_type = ETH_NO_MSG;

  /* Determine the type of Ethernet packet */
  uint16_t eth_msg_type = ethertype(packet);
  /* Type ARP datagram */
  if(eth_msg_type == ethertype_arp)
  {
    /* Validate the input ARP packet */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if(ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet || ntohs(arp_hdr->ar_pro) != arp_prot_type_ipv4
     || arp_hdr->ar_hln != arp_hdw_len_ethernet || arp_hdr->ar_pln != arp_prot_len_ipv4)
    {
      printf( "Error: Invalid ARP packet!\n");
      return;
    }
    uint16_t arp_operation = ntohs(arp_hdr->ar_op);
    /* Detect the type of ARP operation */
    if(arp_operation == arp_op_request)
      eth_type = ETHER_ARP_REQ;
    else if(arp_operation == arp_op_reply)
      eth_type = ETHER_ARP_REP;
  }
  /* Type IP datagram */
  else if(eth_msg_type == ethertype_ip)
  {
    /* Verify the length of the packet */
    if(len < (sizeof(sr_ethernet_hdr_t) + IP_MIN_LEN))
    {
      printf( "Error: Invalid Ethernet-IP length!\n");
      return;
    }
    /* Validate the length and the version field of the IP datagram */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if(ip_hdr->ip_v != 0x4 || ip_hdr->ip_hl != 0x5 || ntohs(ip_hdr->ip_len) <= sizeof(sr_ip_hdr_t))
    {
      printf( "Error: Invalid IP datagram!\n");
      return;
    }
    /* Verify the checksum of the IP header */
    uint16_t ip_hdr_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    if(ip_hdr_cksum != cksum(ip_hdr, sizeof(sr_ip_hdr_t)))
    {
      printf( "Error: Invalid IP checksum|\n");
      return;
    }
    ip_hdr->ip_sum = ip_hdr_cksum;

    /* Verify if the TTL field is 0 */
    if(ip_hdr->ip_ttl == 1)
    {
      printf("Packet TTL expired!\n");
      /* Get the MAC address of the IP datagram that cause TTL expired */
      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
      /* Send ICMP type 11 code 0 */
      sr_icmp_send(sr, eth_hdr->ether_shost, (packet + sizeof(sr_ethernet_hdr_t)), len - sizeof(sr_ethernet_hdr_t), 11, 0, interface);
      return;
    }
    struct sr_if *rcv_if = sr_get_interface(sr, interface);
    /* Case the destination IP address is our router interface */
    if(ip_hdr->ip_dst == rcv_if->ip)
    {
      if(ip_hdr->ip_p == ip_protocol_icmp)
        eth_type = ETHER_IP_TO_US_ICMP;
      else if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp)
        eth_type = ETHER_IP_TO_US_TRACEROUTE;
    }
    else
    {
      eth_type = ETHER_IP_TO_ELSE;
    }
  }

  /* State machine for handle the reception of datap packet */
  switch (eth_type)
  {
  case ETHER_ARP_REQ:
    {
      printf("Received ARP request!\n");
      sr_arp_req_handle(sr, (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)), interface);
    }
    break;
  
  case ETHER_ARP_REP:
    {
      printf("Received ARP reply!\n");
      sr_arp_hdr_t *arp_rep_datagram = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      /* Insert the new MAC address to the cache */
      struct sr_arpreq *arp_req = sr_arpcache_insert(&sr->cache, arp_rep_datagram->ar_sha, arp_rep_datagram->ar_sip);
      if(arp_req == NULL)
        return;
      /* Send all the packet associated with the ARP request */
      struct sr_packet *cur_packet = arp_req->packets;
      while(cur_packet != NULL)
      {
        /* Give the destination MAC address to the Ethernet frame */
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)cur_packet->buf;
        memcpy(eth_hdr->ether_dhost, arp_rep_datagram->ar_sha, ETHER_ADDR_LEN);
        sr_send_packet(sr, cur_packet->buf, cur_packet->len , cur_packet->iface);

        cur_packet = cur_packet->next;
      }
      /* Delete the ARP request */
      sr_arpreq_destroy(&sr->cache, arp_req);
    }
    break;
  /* Case IP packet with ICMP request is sent to us */
  case ETHER_IP_TO_US_ICMP:
    {
      /* Get the MAC address of the IP datagram that cause TTL expired */
      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
      /* Case ICMP reply for NAT operation */
      if(sr->nat.valid)
      {
        struct sr_if* rcv_if = sr_get_interface(sr, interface);
        if(strcmp(rcv_if->name, "eth2") == 0)
        {
          if(! sr_nat_handle(&(sr->nat), packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), nat_inbound))
          {
            printf("Unable to perform NAT, dropping packet ...\n");
            return;
          }
          sr_forward_handle(sr, eth_hdr->ether_shost, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
          return;
        }
      }
      /* Send ICMP echo response type 0 code 0 */
      sr_icmp_req_handle(sr, eth_hdr->ether_shost, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
    }
    break;
  /* Case IP packet with UDP datagram sent to our IP address */
  case ETHER_IP_TO_US_TRACEROUTE:
    {
      printf("Received Treceroute command\n");
      /* Get the MAC address of the IP datagram that cause TTL expired */
      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
      /* Case TCP or UDP for NAT operation */
      if(sr->nat.valid)
      {
        struct sr_if* rcv_if = sr_get_interface(sr, interface);
        if(strcmp(rcv_if->name, "eth2") == 0)
        {
          if(! sr_nat_handle(&(sr->nat), packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), nat_inbound))
          {
            printf("Unable to perform NAT, dropping packet ...\n");
            return;
          }
          sr_forward_handle(sr, eth_hdr->ether_shost, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
          return;
        }
      }
      /* Send ICMP type 3 code 3 */
      sr_icmp_send(sr, eth_hdr->ether_shost, (packet + sizeof(sr_ethernet_hdr_t)), len - sizeof(sr_ethernet_hdr_t), 3, 3, interface);
    }
    break;

  case ETHER_IP_TO_ELSE:
    {
      printf("Receievd forwarding packet\n");
      /* Get the MAC address of the IP datagram that cause TTL expired */
      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
      /* Handle the forwarding task of the router */
      sr_forward_handle(sr, eth_hdr->ether_shost, packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t), interface);
    }
    break;

  default:
    printf( "Error: Inavlid packet type|\n");
    return;
    break;
  }

}/* end sr_ForwardPacket */

/*
 * Function to create the desired ICMP type 3 segment
 * Param icmp_t3_segment: struct that contain the ICMP segment
 * Param ip_datagram: IP datagram that cause the ICMP shout out
 * Param icmp_type: type of the sending ICMP
 * Param icmp_code: code of the sending ICMP
 * Return type: none
*/
void sr_icmp_t3_create(sr_icmp_t3_hdr_t * icmp_t3_segment, uint8_t* ip_datagram,
                           uint8_t icmp_type, uint8_t icmp_code)
{
  /* Verify the input condition */
  if(icmp_t3_segment == NULL || ip_datagram == NULL)
    return;
  /* Fill the ICMP data segment */
  icmp_t3_segment->icmp_type = icmp_type;
  icmp_t3_segment->icmp_code = icmp_code;
  icmp_t3_segment->unused = htons(0);
  icmp_t3_segment->next_mtu = htons(0);
  memcpy(icmp_t3_segment->data, ip_datagram, ICMP_DATA_SIZE);
  /* Compute the checksum for the whole ICMP message */
  icmp_t3_segment->icmp_sum  = 0;
  icmp_t3_segment->icmp_sum = cksum(icmp_t3_segment, sizeof(sr_icmp_t3_hdr_t));
}

/*
 * Function to create the desired ICMP type 0 segment
 * Param icmp_t0_segment: struct that contain the ICMP segment
 * Param rcv_icmp_t0_segment: ICMP request segment
 * Param len: length of the ICMP request segment
 * Param icmp_type: type of the sending ICMP
 * Param icmp_code: code of the sending ICMP
 * Return type: none
*/
void sr_icmp_t0_create(sr_icmp_t0_hdr_t *icmp_t0_segment, uint8_t *rcv_icmp_t0_segment, uint16_t len, uint8_t icmp_type, uint8_t icmp_code)
{
  /* Verify the input condition */
  if(icmp_t0_segment == NULL || rcv_icmp_t0_segment == NULL || len <= sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t0_hdr_t))
    return;

  sr_icmp_t0_hdr_t *rcv_icmp_hdr = (sr_icmp_t0_hdr_t *)rcv_icmp_t0_segment;
  /* Fill the ICMP data segment */
  icmp_t0_segment->icmp_type = icmp_type;
  icmp_t0_segment->icmp_code = icmp_code;
  icmp_t0_segment->icmp_id = rcv_icmp_hdr->icmp_id;
  icmp_t0_segment->icmp_seq = rcv_icmp_hdr->icmp_seq;
  /* Copy the data of the echo to reply msg */
  memcpy(icmp_t0_segment->data, rcv_icmp_t0_segment + sizeof(sr_icmp_t0_hdr_t), len - sizeof(sr_icmp_t0_hdr_t));
  icmp_t0_segment->icmp_sum  = 0;
  icmp_t0_segment->icmp_sum = cksum(icmp_t0_segment, len);
}

/*
 * Function to create the IP datagram
 * Param sr_ip_datagram: structure to contain the datagram
 * Param data: data to be carried by the IP datagram
 * Param len: length of the data
 * Param protocol: the code for the upper protocol 
 * Param src_ip_addr: the IP address of the sender
 * Param dest_ip_addr: the IP address of the destination 
 * Return value: none
*/
void sr_ip_create(sr_ip_datagram *ip_datagram, uint8_t *data, 
                          uint16_t len, uint8_t protocol, uint32_t src_ip_addr,
                          uint32_t dest_ip_addr)
{
  /* Verify input condition */
  if(ip_datagram == NULL || data == NULL)
    return;
  
  /* Fill the IP datagram */
  ip_datagram->ip_hdr.ip_v = 0x4;
  ip_datagram->ip_hdr.ip_hl = 0x5;
  ip_datagram->ip_hdr.ip_tos = 0;
  ip_datagram->ip_hdr.ip_len = htons(sizeof(sr_ip_hdr_t) + len);
  ip_datagram->ip_hdr.ip_ttl = 40;
  ip_datagram->ip_hdr.ip_p = protocol;
  ip_datagram->ip_hdr.ip_src = src_ip_addr;
  ip_datagram->ip_hdr.ip_dst = dest_ip_addr;
  /* Add the checksum field */
  ip_datagram->ip_hdr.ip_sum = 0;
  ip_datagram->ip_hdr.ip_sum = cksum(ip_datagram, sizeof(sr_ip_hdr_t));
  /* Copy the data to the data field */
  memcpy(ip_datagram->ip_data, data, len);
}

/*
 * Function to create the Ethernet packet frame
 * Param ethernet_packet: structure that contains the ethernet packet
 * Param data: data to be carried by the ethernet frame
 * Param len: length of the data to be carried
 * Param src_mac_addr: MAC address of the source device
 * Param dest_mac_addr: MAC address of the destination device
 * Return value: none
*/
void sr_ethernet_create(sr_ethernet_packet *ethernet_packet, 
                              uint8_t *data, uint16_t len, uint8_t *src_mac_addr,
                              uint8_t *dest_mac_addr, enum sr_ethertype type)
{
  /* Verify the input condition */
  if(ethernet_packet == NULL || data == NULL || src_mac_addr == NULL || dest_mac_addr == NULL)
    return;
  
  /* Fill the ethernet frame */
  memcpy(ethernet_packet->ethernet_hdr.ether_shost, src_mac_addr, ETHER_ADDR_LEN);
  /* Convert the MAC address host byte order to network byte order */
  memcpy(ethernet_packet->ethernet_hdr.ether_dhost, dest_mac_addr, ETHER_ADDR_LEN);
  ethernet_packet->ethernet_hdr.ether_type = htons(type);
  memcpy(ethernet_packet->ethernet_data, data, len);
}

/*
 * Function to send the ICMP packet over the Ethernet network
 * Param sr: the information of the current router
 * Param ip_datagram: the IP datagram caused the ICMP shout out
 * Param len: length of the IP datagram
 * Param icmp_type: type of the sending ICMP
 * Param icmp_code: code of the sending ICMP
 * Return type: none
*/
void sr_icmp_send(struct sr_instance *sr, uint8_t *dest_mac_addr, uint8_t *ip_datagram, uint16_t len, uint8_t icmp_type, uint8_t icmp_code, char *iface)
{
  /* Verify input conditions */
  if(sr == NULL || dest_mac_addr == NULL || ip_datagram == NULL || iface == NULL)
    return;

  uint16_t icmp_hdr_len;
  void *icmp_segment = NULL;
  /* Craete the ICMP segment */
  if(icmp_type == 3 || icmp_type == 11)
  {
    icmp_segment = (sr_icmp_t3_hdr_t *)calloc(sizeof(sr_icmp_t3_hdr_t), 1);
    if(icmp_segment == NULL)
    {
      printf( "Error: Unable to create ICMP segment!\n");
      return;
    }
    sr_icmp_t3_create(icmp_segment, ip_datagram, icmp_type, icmp_code);
    icmp_hdr_len = sizeof(sr_icmp_t3_hdr_t);
  }
  else if(icmp_type == 0)
  {
    icmp_segment = (sr_icmp_t0_hdr_t *)calloc(len - sizeof(sr_ip_hdr_t), 1);
    if(icmp_segment == NULL)
    {
      printf( "Error: Unable to create ICMP segment!\n");
      return;
    }
    sr_icmp_t0_create(icmp_segment, ip_datagram + sizeof(sr_ip_hdr_t), len - sizeof(sr_ip_hdr_t), icmp_type, icmp_code);
    icmp_hdr_len = len - sizeof(sr_ip_hdr_t);
  }
  else
  {
    printf( "Error: Invalid ICMP type!\n");
    return;
  }

  /* Create the IP datagram and attach the ICMP segment as the data field of the IP datagram */
  sr_ip_datagram *send_ip_datagram = (sr_ip_datagram *)calloc(sizeof(sr_ip_datagram) + icmp_hdr_len, 1);
  if(send_ip_datagram == NULL)
  {
    printf( "Error: Unable to create the IP datagram!\n");
    return;
  }
  /* Get the source and destination IP address for the IP datagram */
  sr_ip_hdr_t *rcv_ip_hdr = (sr_ip_hdr_t *)ip_datagram;
  uint32_t dest_send_ip_addr = rcv_ip_hdr->ip_src;
  /* Get the IP address of the received interface of the router */
  struct sr_if *rcv_if = sr_get_interface(sr, iface);
  uint32_t src_send_ip_addr;
  if(icmp_type == 11)
    src_send_ip_addr = rcv_if->ip;
  else
    src_send_ip_addr = rcv_ip_hdr->ip_dst;

  sr_ip_create(send_ip_datagram, (uint8_t *)icmp_segment, icmp_hdr_len, (uint8_t)ip_protocol_icmp, src_send_ip_addr, dest_send_ip_addr);

  /* Create the Ethernet frame to contains the above IP and ICMP segments */
  sr_ethernet_packet *ethernet_packet = (sr_ethernet_packet *)calloc(sizeof(sr_ethernet_packet) + sizeof(sr_ip_hdr_t) + icmp_hdr_len, 1);
  if(ethernet_packet == NULL)
  {
    printf( "Error: Unable to create the Ethernet packet!\n");
    return;
  }
  uint8_t eth_src_mac_addr[ETHER_ADDR_LEN];
  memcpy(eth_src_mac_addr, rcv_if->addr, ETHER_ADDR_LEN);
  sr_ethernet_create(ethernet_packet, (uint8_t *)send_ip_datagram, sizeof(sr_ip_hdr_t) + icmp_hdr_len, eth_src_mac_addr, dest_mac_addr, ethertype_ip);
  /* Send the Ethernet frame  */
  sr_send_packet(sr, (uint8_t *)ethernet_packet, sizeof(sr_ethernet_packet) + sizeof(sr_ip_hdr_t) + icmp_hdr_len, iface);

  /* Deallocate memory */
  free(icmp_segment);
  free(send_ip_datagram);
  free(ethernet_packet);
}

/*
 * Function handle the ICMP request type 8 - code 0
 * Param sr: struct store the state information of the router
 * Param dest_mac_addr: MAC address of the sender of the ICMP request
 * Param ip_datagram: IP datagram associated with the packet
 * Param len: length of the IP datagram
 * Param iface: ICMP request received interface
 * Return value: none
*/
static void sr_icmp_req_handle(struct sr_instance *sr, uint8_t *dest_mac_addr, uint8_t *ip_datagram, uint16_t len, char *iface)
{
  /* Verify the checksum of the ICMP request */
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_datagram + sizeof(sr_ip_hdr_t));
  uint16_t icmp_hdr_cksum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  if(icmp_hdr_cksum != cksum(ip_datagram + sizeof(sr_ip_hdr_t), len - sizeof(sr_ip_hdr_t)))
  {
    printf( "Error: ICMP request wrong checksum!\n");
    return;
  }
  icmp_hdr->icmp_sum = icmp_hdr_cksum;
  /* Send the reply */
  if(icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0)
  {
    printf("Received Ping request!\n");
    sr_icmp_send(sr, dest_mac_addr, ip_datagram, len, 0, 0, iface);
  }
}

/*
 * Function to create the ARP reply datagram
 * Param rep_ arp_datagram: struct to store the reply ARP datagram
 * Param req_arp_datagram: struct to store the request ARP datagram
 * Param target_mac_addr: the MAC address of the IP address in the ARP request
 * Return value: none
*/
static void sr_arp_rep_create(sr_arp_hdr_t *rep_arp_datagram, sr_arp_hdr_t* arp_req_datagram, uint8_t* target_mac_addr)
{
  /* Verify input condition */
  if(rep_arp_datagram == NULL || arp_req_datagram == NULL || target_mac_addr == NULL)
    return;

  /* Fill the ARP reply datagram */
  rep_arp_datagram->ar_hrd = htons(arp_hrd_ethernet);
  rep_arp_datagram->ar_pro = htons(arp_prot_type_ipv4);
  rep_arp_datagram->ar_hln = arp_hdw_len_ethernet;
  rep_arp_datagram->ar_pln = arp_prot_len_ipv4;
  rep_arp_datagram->ar_op = htons(arp_op_reply);
  memcpy(rep_arp_datagram->ar_sha, target_mac_addr, ETHER_ADDR_LEN);
  /* Convert the host byte order to network byte order */
  rep_arp_datagram->ar_sip = arp_req_datagram->ar_tip;
  memcpy(rep_arp_datagram->ar_tha, arp_req_datagram->ar_sha, ETHER_ADDR_LEN);
  rep_arp_datagram->ar_tip = arp_req_datagram->ar_sip;
}

/*
 * Function to handle the ARP request sent to our router
 * Param sr: struct contain current state information of the router
 * Param arp_hdr: header of ARP request datagram
 * Param iface: the interface received the ARP request
 * Return type: none
*/
static void sr_arp_req_handle(struct sr_instance *sr, sr_arp_hdr_t *req_arp_hdr, char *iface)
{
  /* Verify input condition */
  if(sr == NULL || req_arp_hdr == NULL || iface == NULL)
    return;

  /* Check if the target IP address is one of our router IP address */
  struct sr_if* rcv_if = sr_get_interface(sr, iface);
  if(req_arp_hdr->ar_tip != rcv_if->ip)
  {
    printf("Not out IP address, ignoring ...\n");
    return;
  }
  
  /* Create the ARP reply datagram */
  sr_arp_hdr_t *rep_arp_datagram = (sr_arp_hdr_t *)calloc(sizeof(sr_arp_hdr_t), 1);
  if(rep_arp_datagram == NULL)
  {
    printf( "Error: Unable to create ARP reply datagram!\n");
    return;
  }
  sr_arp_rep_create(rep_arp_datagram, req_arp_hdr, rcv_if->addr);
  /* Create the Ehternet frame to carry the ARP reply */
  sr_ethernet_packet *eth_packet = (sr_ethernet_packet *)calloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), 1);
  if(eth_packet == NULL)
  {
    printf( "Error: Unable to create Ehternet frame!\n");
    return;
  }
  sr_ethernet_create(eth_packet, (uint8_t *)rep_arp_datagram, sizeof(sr_arp_hdr_t), rcv_if->addr, req_arp_hdr->ar_sha, ethertype_arp);
  /* Send the Ehternet packet over network */
  sr_send_packet(sr, (uint8_t *)eth_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), iface);

  /* Deallocate memory buffers */
  free(rep_arp_datagram);
  free(eth_packet);
}

/*
 * Function to get the interface with the longest prefix match
 * Param sr: information of our router
 * Param target_ip_address: IP address of our target destination
 * Param rcv_iface: packet received interface
 * Return value: interface with the longest prefix match (NULL if no prefix match)
*/
static struct sr_rt *sr_get_forward_interface(struct sr_instance *sr, uint32_t target_ip_addr, char *rcv_iface)
{
  /* Verify input condition */
  if(sr == NULL || rcv_iface == NULL)
    return NULL;
  /* Traverse the routing table */
  struct sr_rt *cur_rt = sr->routing_table;
  struct sr_rt *forward_rt = NULL;
  uint32_t ip_max_match = UINT32_MAX;
  while(cur_rt != NULL)
  {
    /* Check if the current interface is the received interface */
    if(strcmp(cur_rt->interface, rcv_iface) == 0)
    {
      cur_rt = cur_rt->next;
      continue;
    }
    /* Get the prefix of the routing table interface */
    uint32_t ip_prefix = (uint32_t)cur_rt->gw.s_addr & (uint32_t)cur_rt->mask.s_addr;
    uint32_t ip_match = ip_prefix ^ target_ip_addr;
    /* Check if the number of matching number suit the subnet mask */
    uint32_t ip_match_rate = ip_match & (uint32_t)cur_rt->mask.s_addr;
    /* The number of prefix match not enough for the subnet mask */
    if(ip_match_rate > 0)
    {
      cur_rt = cur_rt->next;
      continue;
    }
    else
    {
      if(ip_match < ip_max_match)
      {
        ip_max_match = ip_match;
        forward_rt = cur_rt;
      }
    }
    cur_rt = cur_rt->next;
  }
  return forward_rt;
}

/*
 * Function to handle the frowarding task of the router
 * Param sr: struct that store the state inforamtion of our router
 * Param dest_mac_addr: MAC address of the sender (used for ICMP feedback)
 * Param ip_datagram: the IP datagram required to be forwarded
 * Param len: Length of the IP datagram
 * Param iface: interface that received the datagram
 * Return value: none
*/
static void sr_forward_handle(struct sr_instance *sr, uint8_t *dest_mac_addr, uint8_t *ip_datagram, uint16_t len, char *iface)
{
  /* Verify input condition */
  if(sr == NULL || ip_datagram == NULL || iface == NULL)
    return;

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)ip_datagram;
  /* Get the routing table to forward the message to */
  struct sr_rt *forward_rt = sr_get_forward_interface(sr, ip_hdr->ip_dst, iface);
  /* Case no matching found */
  if(forward_rt == NULL)
  {
    /* Check if the destination IP address is the IP address of other interface */
    struct sr_if *cur_if = sr->if_list;
    while(cur_if != NULL)
    {
      if(cur_if->ip == ip_hdr->ip_dst)
      {
        break;
      }
      cur_if = cur_if->next;
    }
    /* Case the destination IP address is one of our interfaces */
    if(cur_if != NULL)
    {
      /* Case Ping */
      if(ip_hdr->ip_p == ip_protocol_icmp)
      {
        sr_icmp_req_handle(sr, dest_mac_addr, ip_datagram, len, iface);
      }
      /* Case Traceroute */
      else if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp)
      {
        sr_icmp_send(sr, dest_mac_addr, ip_datagram, len, 3, 3, iface);
      }
    }
    else
    {
      printf("No interface matching found!\n");
      /* Send ICMP type 3 code 0 (destination net unreachable) */
      sr_icmp_send(sr, dest_mac_addr, ip_datagram, len, 3, 0, iface);
    }
    return;
  }
  /* Perform NAT operations for outbound packet */
  if(sr->nat.valid)
  {
    struct sr_if* rcv_if = sr_get_interface(sr, iface);
    if(strcmp(rcv_if->name, "eth1") == 0)
    {
      if(! sr_nat_handle(&(sr->nat), ip_datagram, len, nat_outbound))
      {
        printf("Unable to perform NAT, dropping packet ...\n");
        return;
      }
    }
  }
  /* Decrement TTL field and recalculate checksum */
  ip_hdr->ip_ttl -= 1;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  /* Get the interface for forwarding the message */
  struct sr_if *forward_if = sr_get_interface(sr, forward_rt->interface);
  if(forward_if == NULL)
  {
    printf( "Error: Unable to find interface!\n");
    return;
  }
  /* Create the Ethernet frame */
  sr_ethernet_packet *eth_packet = (sr_ethernet_packet *)calloc(sizeof(sr_ethernet_hdr_t) + len, 1);
  if(eth_packet == NULL)
  {
    printf( "Error: Unable to create Ethernet packet!\n");
    return;
  }
  /* Look the MAC address of the detsination IP address in the cache */
  struct sr_arpentry *arp_cache = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
  /* In case MAC address in the cache */
  if(arp_cache != NULL)
  {
    uint8_t cache_dest_mac_addr[ETHER_ADDR_LEN];
    memcpy(cache_dest_mac_addr, arp_cache->mac, ETHER_ADDR_LEN);
    /* Convert the destination MAC address to network byte order */
    sr_ethernet_create(eth_packet, ip_datagram, len, forward_if->addr, cache_dest_mac_addr, ethertype_ip);
    /* Send the Ethernet frame over the network */
    sr_send_packet(sr, (uint8_t *)eth_packet, sizeof(sr_ethernet_hdr_t) + len, forward_if->name);
    /* Deallocate buffer */
    free(arp_cache);
    free(eth_packet);
  }
  /* Case no MAC address found in cache */ 
  else
  {
    /* Create the Ethernet frame with empty destination MAC address */ 
    uint8_t empty_mac_addr[ETHER_ADDR_LEN];
    memset(empty_mac_addr, 0, ETHER_ADDR_LEN);
    sr_ethernet_create(eth_packet, ip_datagram, len, forward_if->addr, empty_mac_addr, ethertype_ip);
    /* Add the packet to the queue of ARP requests */
    sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, (uint8_t *)eth_packet, dest_mac_addr, sizeof(sr_ethernet_hdr_t) + len, forward_rt->interface, iface);
  }
}