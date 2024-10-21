
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include "sr_utils.h"
#include "sr_protocol.h"
#include "sr_router.h"

const char eth2_ip_addr[] =  "184.72.104.221";

/********************************** Private function prototypes **************************************/
static int sr_nat_icmp_handle(struct sr_nat *nat, uint8_t *ip_datagram, uint16_t len, sr_nat_direction nat_dir);
static int sr_nat_tcp_handle(struct sr_nat *nat, uint8_t *ip_datagram, uint16_t len, sr_nat_direction nat_dir);
static void sr_nat_mapping_remove(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);
static uint16_t sr_nat_port_num(void);
static void sr_nat_timeout_handle(struct sr_nat *nat);

int sr_nat_init(struct sr_nat *nat, uint8_t icmp_query_timeout, 
                  uint16_t tcp_estab_idle_timeout, uint16_t tcp_transit_idle_timeout) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */
  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */
  srand(time(NULL));
  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->valid = 1;
  /* Set the timeout condition for the NAT module */
  if(icmp_query_timeout < 60)
    icmp_query_timeout = 60;
  nat->icmp_query_timeout = icmp_query_timeout;

  if(tcp_estab_idle_timeout < 7440)
    tcp_estab_idle_timeout = 7440;
  nat->tcp_est_idle_timeout = tcp_estab_idle_timeout;

  if(tcp_transit_idle_timeout < 300)
    tcp_transit_idle_timeout = 300;
  nat->tcp_trans_idle_timeout = tcp_transit_idle_timeout;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
  pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    /* handle periodic tasks here */
    sr_nat_timeout_handle(nat);


    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  for(copy = nat->mappings; copy != NULL; copy = copy->next)
  {
    if(copy->aux_ext == aux_ext && copy->type == type)
      break;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  for(copy = nat->mappings; copy != NULL; copy = copy->next)
  {
    if(copy->ip_int == ip_int && copy->aux_int == aux_int && copy->type == type)
      break;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, sr_nat_tcp_state conn_state) { 
  pthread_mutex_lock(&(nat->lock));
  
  /* Loop until we find a unique port number */
  uint16_t port_num;
  uint8_t port_match;
  struct sr_nat_mapping *mapping = NULL;
  while(1)
  {
    /* handle insert here, create a mapping, and then return a copy of it */
    port_match = 0;
    port_num = sr_nat_port_num();
    /* Traverse to the end position of the linked list */
    for(mapping = nat->mappings; mapping != NULL; mapping = mapping->next)
    {
      if(mapping->aux_ext == port_num)
      {
        port_match = 1;
      }
    }
    if(! port_match)
      break;
  }
  mapping = (struct sr_nat_mapping *)calloc(sizeof(struct sr_nat_mapping), 1);
  mapping->type = type;
  mapping->ip_int = ip_int;
  inet_pton(AF_INET, eth2_ip_addr, &(mapping->ip_ext));
  mapping->aux_int = aux_int;
  mapping->aux_ext = port_num;
  mapping->last_updated = time(NULL);

  struct sr_nat_connection *conn = (struct sr_nat_connection *)calloc(sizeof(struct sr_nat_connection), 1);
  conn->tcp_state = conn_state;
  conn->next = NULL;
  mapping->conns = conn;
  /* Add mapping to the head of the linked list */
  mapping->next = nat->mappings;
  nat->mappings = mapping;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

/*
 * Function to remove the connection state of the conneciton mapping
*/
static void sr_nat_mapping_remove(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{
  /* Lock the mutex */
  pthread_mutex_lock(&(nat->lock));
  
  /* Verify input condition */
  if(nat == NULL || nat->mappings == NULL)
    return;
  /* Search for the dedicated mapping */
  struct sr_nat_mapping *nat_mapping = nat->mappings;
  struct sr_nat_mapping *prev_nat_mapping;
  /* Case linked list has only 1 mapping */
  if(nat_mapping->ip_int == ip_int && nat_mapping->aux_int == aux_int && nat_mapping->type == type)
  {
    nat->mappings = nat_mapping->next;
    if(nat_mapping->conns != NULL)
      free(nat_mapping->conns);
    free(nat_mapping);
    return;
  }
  /* Traverse to the previous mapping */
  while(nat_mapping != NULL && (nat_mapping->ip_int != ip_int || nat_mapping->aux_int != aux_int || nat_mapping->type != type))
  {
    prev_nat_mapping = nat_mapping;
    nat_mapping = nat_mapping->next;
  }
  /* Case no mapping found */
  if(nat_mapping == NULL)
    return;
  /* Remove the corresponding mapping */
  prev_nat_mapping->next = nat_mapping->next;
  if(nat_mapping->conns != NULL)
      free(nat_mapping->conns);
  free(nat_mapping);

  pthread_mutex_unlock(&(nat->lock));
}

/*
 * Function to generate a random port number > 1023 
 * Return value: port number (uint16_t)
*/
static uint16_t sr_nat_port_num(void)
{
  uint16_t port_num = rand() % (UINT16_MAX - 1024 + 1) + 1024;
  return htons(port_num);
}

/*
 * Function to handle the NAT operation of the ICMP segment
 * Param sr: the struct store the information of the router
 * Param ip_datagram: The IP datagram containing the ICMP segment
 * Param len: length of the corresponding IP datagram
 * Return value: 1: SUCCESS - 0: FAIL
*/
static int sr_nat_icmp_handle(struct sr_nat *nat, uint8_t *ip_datagram, uint16_t len, sr_nat_direction nat_dir)
{
  /* Verify input condition */
  if(nat == NULL || ip_datagram == NULL)
    return 0;

  printf("NAT ICMP handling\n");

  /* Create and insert the mapping */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)ip_datagram;
  /* Check if the ICMP segment belongs to type 8 */
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_datagram + sizeof(sr_ip_hdr_t));
  /* Case outbound direction */
  if(nat_dir == nat_outbound)
  {
    if(icmp_hdr->icmp_type == 8)
    {
      sr_icmp_t0_hdr_t *icmp_t0_hdr = (sr_icmp_t0_hdr_t *)(ip_datagram + sizeof(sr_ip_hdr_t));
      struct sr_nat_mapping *nat_mapping = NULL;
      /* Check if the mapping has already exist */
      nat_mapping = sr_nat_lookup_internal(nat, ip_hdr->ip_src, icmp_t0_hdr->icmp_id, nat_mapping_icmp);
      if(nat_mapping == NULL)
      {
        nat_mapping = sr_nat_insert_mapping(nat, ip_hdr->ip_src, icmp_t0_hdr->icmp_id, nat_mapping_icmp, nat_icmp);
        if(nat_mapping == NULL)
        {
          printf("Error: Unable to insert new mapping!\n");
          return 0;
        }
      }
      /* Replace the internal ID by the global external ID */
      icmp_t0_hdr->icmp_id = nat_mapping->aux_ext;
      /* Recompute the ICMP checksum */
      icmp_t0_hdr->icmp_sum = 0;
      icmp_t0_hdr->icmp_sum = cksum(ip_datagram + sizeof(sr_ip_hdr_t), len - sizeof(sr_ip_hdr_t));
      /* Update the last used time */
      nat_mapping->last_updated = time(NULL);
      /* Change the source IP address */
      ip_hdr->ip_src = nat_mapping->ip_ext;
      /* Recompute IP header checksum */
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_datagram, sizeof(sr_ip_hdr_t));
    }
  }
  /* Case inbound direction */
  else if(nat_dir == nat_inbound)
  {
    if(icmp_hdr->icmp_type == 0)
    {
      sr_icmp_t0_hdr_t *icmp_t0_hdr = (sr_icmp_t0_hdr_t *)(ip_datagram + sizeof(sr_ip_hdr_t));
      /* Get the mapping associated with the ICMP packet */
      struct sr_nat_mapping *nat_mapping = sr_nat_lookup_external(nat, icmp_t0_hdr->icmp_id, nat_mapping_icmp);
      if(nat_mapping == NULL)
      {
        printf("Error: Unable to find external mapping!\n");
        return 0;
      }
      /* Replace the global external ID with the internal ID */
      icmp_t0_hdr->icmp_id = nat_mapping->aux_int;
      /* Recompute ICMP checksum */
      icmp_hdr->icmp_sum = 0;
      icmp_hdr->icmp_sum = cksum(ip_datagram + sizeof(sr_ip_hdr_t), len - sizeof(sr_ip_hdr_t));
      /* Update the last used time */
      nat_mapping->last_updated = time(NULL);
      /* Replace the destination IP address */
      ip_hdr->ip_dst = nat_mapping->ip_int;
      /* Recompute IP header checksum */
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_datagram, sizeof(sr_ip_hdr_t));
    }
  }
  return 1;
}

/*
 * Function to handle the NAT operation of the TCP connection
 * Param sr: the struct store the information of the router
 * Param ip_datagram: The IP datagram containing the ICMP segment
 * Param len: length of the corresponding IP datagram
 * Return value: 1: SUCCESS - 0: FAIL
*/
static int sr_nat_tcp_handle(struct sr_nat *nat, uint8_t *ip_datagram, uint16_t len, sr_nat_direction nat_dir)
{
  /* Verify input condition */
  if(nat == NULL || ip_datagram == NULL)
    return 0;
  
  printf("NAT TCP handling\n");

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)ip_datagram;
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(ip_datagram + sizeof(sr_ip_hdr_t));
  /* Case outbound direction */
  if(nat_dir == nat_outbound)
  {
    struct sr_nat_mapping *nat_mapping = NULL;
    /* Case SYN segment*/
    if(tcp_hdr->flags & TH_SYN)
    {
      /* Check if we already has the unsolicited connection */
      nat_mapping = sr_nat_lookup_internal(nat, ip_hdr->ip_dst, tcp_hdr->port_dest, nat_mapping_tcp);
      if(nat_mapping != NULL)
      {
        /* Remove the old mapping */
        sr_nat_mapping_remove(nat, nat_mapping->ip_int, nat_mapping->aux_int, nat_mapping_tcp);
      }
      /* Add new mapping for the TCP connection */
      nat_mapping = sr_nat_insert_mapping(nat, ip_hdr->ip_src, tcp_hdr->port_src, nat_mapping_tcp, nat_tcp_syn_1);
      if(nat_mapping == NULL)
      {
        printf("Error: Unable to add new TCP mapping!\n");
        return 0;
      }
    }
    /* Case FIN segment */
    else if(tcp_hdr->flags & TH_FIN)
    {
      /* Look for the conneciton mapping */
      nat_mapping = sr_nat_lookup_internal(nat, ip_hdr->ip_src, tcp_hdr->port_src, nat_mapping_tcp);
      if(nat_mapping == NULL)
      {
        printf("Error: Unable to find the TCP mapping!\n");
        return 0;
      }
      /* Update the state of the connection */
      if(nat_mapping->conns->tcp_state == nat_tcp_fin_1)
        nat_mapping->conns->tcp_state = nat_tcp_fin_2;
      else if(nat_mapping->conns->tcp_state == nat_tcp_established)
        nat_mapping->conns->tcp_state = nat_tcp_fin_1;
      /* Update the time of the connection */
      nat_mapping->last_updated = time(NULL);
    }
    /* Case data and ACK segments */
    else
    {
      /* Look for the conneciton mapping */
      nat_mapping = sr_nat_lookup_internal(nat, ip_hdr->ip_src, tcp_hdr->port_src, nat_mapping_tcp);
      if(nat_mapping == NULL)
      {
        printf("Error: Unable to find the TCP mapping!\n");
        return 0;
      }
      /* Update the state of the connection in case of ACK */
      if(tcp_hdr->flags & TH_ACK)
      {
        if(nat_mapping->conns->tcp_state == nat_tcp_syn_2)
          nat_mapping->conns->tcp_state = nat_tcp_established;
        else if(nat_mapping->conns->tcp_state == nat_tcp_fin_2)
          nat_mapping->conns->tcp_state = nat_tcp_full_close;
      }
      /* Update the time of the connection */
      nat_mapping->last_updated = time(NULL);
    }
    /* Replace source port number and recalculate TCP checksum */
    tcp_hdr->port_src = nat_mapping->aux_ext;
    tcp_hdr->cksum = 0;
    tcp_hdr->cksum = cksum(tcp_hdr, len - sizeof(sr_ip_hdr_t));
    /* Replace the source IP address and recalculate the iP header checksum */
    ip_hdr->ip_src = nat_mapping->ip_ext;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  }
  /* Case inbound packet */
  if(nat_dir == nat_inbound)
  {
    struct sr_nat_mapping *nat_mapping = NULL;
    /* Case SYN packet */
    if(tcp_hdr->flags & TH_SYN)
    {
      /* Check if it already has that specific TCP connection */
      nat_mapping = sr_nat_lookup_external(nat, tcp_hdr->port_dest, nat_mapping_tcp);
      /* Unsolicited inbound SYN case */
      if(nat_mapping == NULL)
      {
        /* Add connection mapping */
        nat_mapping = sr_nat_insert_mapping(nat, ip_hdr->ip_src, tcp_hdr->port_src, nat_mapping_tcp, nat_tcp_unsolicited_inbound_start);
        if(nat_mapping == NULL)
        {
          printf("Error: Unable to add new TCP unsolicited mapping!\n");
          return 0;
        }
      }
      else 
      {
        /* Received the 2nd SYN */
        if(nat_mapping->conns->tcp_state == nat_tcp_syn_1)
          nat_mapping->conns->tcp_state = nat_tcp_syn_2;
        else 
          return 0;
      }
    }
    /* Case FIN paacket */
    else if(tcp_hdr->flags & TH_FIN)
    {
      /* Look for the conneciton mapping */
      nat_mapping = sr_nat_lookup_external(nat, tcp_hdr->port_dest, nat_mapping_tcp);
      if(nat_mapping == NULL)
      {
        printf("Error: Unable to find the TCP mapping!\n");
        return 0;
      }
      /* Update the state of the connection */
      if(nat_mapping->conns->tcp_state == nat_tcp_fin_1)
        nat_mapping->conns->tcp_state = nat_tcp_fin_2;
      else if(nat_mapping->conns->tcp_state == nat_tcp_established)
        nat_mapping->conns->tcp_state = nat_tcp_fin_1;
      /* Update the time of the connection */
      nat_mapping->last_updated = time(NULL);
    }
    /* Case data and ACK segments */
    else 
    {
      /* Look for the conneciton mapping */
      nat_mapping = sr_nat_lookup_external(nat, tcp_hdr->port_dest, nat_mapping_tcp);
      if(nat_mapping == NULL)
      {
        printf("Error: Unable to find the TCP mapping!\n");
        return 0;
      }
      /* Update the state of the connection in case of ACK */
      if(tcp_hdr->flags & TH_ACK)
      {
        if(nat_mapping->conns->tcp_state == nat_tcp_fin_2)
          nat_mapping->conns->tcp_state = nat_tcp_full_close;
      }
      /* Update the time of the connection */
      nat_mapping->last_updated = time(NULL);
    }
    /* Replace destination port number and recalculate TCP cheksum */
    tcp_hdr->port_dest = nat_mapping->aux_int;
    tcp_hdr->cksum = 0;
    tcp_hdr->cksum = cksum(tcp_hdr, len - sizeof(sr_ip_hdr_t));
    /* Replace destination IP and recalculate IP header checksum */
    ip_hdr->ip_dst = nat_mapping->ip_int;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_datagram, sizeof(sr_ip_hdr_t));
  }
}

/*
 * Function to handle the overall NAT operation
 * Param sr: struct to store the state information of the router
 * Param ip_datagram: IP datagram sent to the router
 * Param len: length of the corresponding datagram
 * Param iface: interface that received the message
 * Return value: 1: SUCCESS - 0: FAIL
*/
int sr_nat_handle(struct sr_nat *nat, uint8_t *ip_datagram, uint16_t len, sr_nat_direction nat_dir)
{
  int state = 0;
  /* Verify input condition */
  if(nat == NULL || ip_datagram == NULL)
    return 0;

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)ip_datagram;
  /* Case ICMP message*/
  if(ip_hdr->ip_p == ip_protocol_icmp)
  {
    state = sr_nat_icmp_handle(nat, ip_datagram, len, nat_dir);
  }
  /* Case TCP message */
  else if(ip_hdr->ip_p == ip_protocol_tcp)
  {
    state = sr_nat_tcp_handle(nat, ip_datagram, len, nat_dir);
  }
  return state;
}

/*
 * Function for timeout handle of NAT mappings
 * Param nat: struct store the information of the NAT module of the router
 * Return value: none
*/
static void sr_nat_timeout_handle(struct sr_nat *nat)
{
  /* Verify input condition */
  if(nat == NULL || nat->mappings == NULL || nat->valid == 0)
    return;
  
  time_t cur_time = time(NULL);
  struct sr_nat_mapping *mapping = nat->mappings;
  /* Traverse the mapping for timeout check */
  while(mapping != NULL)
  {
    /* Case ICMP mapping */
    if(mapping->type == nat_mapping_icmp)
    {
      if(difftime(cur_time, mapping->last_updated) > nat->icmp_query_timeout)
      {
        struct sr_nat_mapping *del_mapping = mapping;
        mapping = mapping->next;
        sr_nat_mapping_remove(nat, del_mapping->ip_int, del_mapping->aux_int, nat_mapping_icmp);
        continue;
      }
    }
    /* Case TCP mapping */
    else if(mapping->type == nat_mapping_tcp)
    {
      /* Case unsolicited inbound SYN */
      if(mapping->conns->tcp_state == nat_tcp_unsolicited_inbound_start && 
        difftime(cur_time, mapping->last_updated) > UNSOLICITED_INBOUND_TIMEOUT)
      {
        struct sr_nat_mapping *del_mapping = mapping;
        mapping = mapping->next;
        /* Send ICMP type 3 code 3*/
        sr_nat_mapping_remove(nat, del_mapping->ip_int, del_mapping->aux_int, nat_mapping_tcp);
        continue;
      }
      else if((mapping->conns->tcp_state == nat_tcp_syn_1 || mapping->conns->tcp_state == nat_tcp_syn_2)
              && difftime(cur_time, mapping->last_updated) > nat->tcp_trans_idle_timeout)
      {
        struct sr_nat_mapping *del_mapping = mapping;
        mapping = mapping->next;
        sr_nat_mapping_remove(nat, del_mapping->ip_int, del_mapping->aux_int, nat_mapping_tcp);
        continue;
      }
      else if(mapping->conns->tcp_state == nat_tcp_established 
              && difftime(cur_time, mapping->last_updated) > nat->tcp_est_idle_timeout)
      {
        struct sr_nat_mapping *del_mapping = mapping;
        mapping = mapping->next;
        sr_nat_mapping_remove(nat, del_mapping->ip_int, del_mapping->aux_int, nat_mapping_tcp);
        continue;
      }
    }
    mapping = mapping->next;
  }
}