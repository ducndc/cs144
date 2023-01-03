/******************************************************************************
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
 *****************************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/**
 * Method: and_operator(uint32_t ip, struct in_addr mask) 
 * Scope: static
 *
 * This method is called each time the router want to and between IP and MASK
 */
static uint32_t and_operator(uint32_t ip, struct in_addr mask);

/**
 * Method: is_if_list(struct sr_instance *sr, uint32_t dst_ip) 
 * Scope: static
 *
 * This method is called each time the router want to check destination IP of  
 * packets to interface
 */
static uint8_t is_if_list(struct sr_instance *sr, uint32_t dst_ip);

/**
 * Method: sr_send_icmp_reply(struct sr_instance *sr, uint8_t *buff,
 *                            unsigned int len, char *interface)
 * Scope: global
 *
 * This method is called each time the router want to send a ICMP reply
 * on the interface 
 */
static void sr_send_icmp_reply(struct sr_instance *sr, uint8_t *buff,
                               unsigned int len, char *interface);

/**
 * Method: sr_send_icmp_host_unreachable(struct sr_instance *sr,
 *                                       struct sr_arpreq *req)
 * Scope: global
 *
 * This method is called each time the router want to send a ICMP host 
 * unreachable on the interface 
 */
static void 
sr_send_icmp_unreachable(struct sr_instance *sr, uint8_t *packet, char *iface,
                         uint8_t icmp_type, uint8_t icmp_code);

/**
 * Method: sr_send_arp_reply(struct sr_instance *sr, uint8_t *buff, 
 *                           unsigned int len, char* interface)
 * Scope: static
 *
 * This method is called each time the router receives a ARP request packet 
 * on the interface and send ARP reply 
 */
static void sr_send_arp_reply(struct sr_instance *sr, uint8_t *buff, 
                  unsigned int len, char *interface);

/*----------------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *--------------------------------------------------------------------------*/
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

/*----------------------------------------------------------------------------
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
 *--------------------------------------------------------------------------*/
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

 /* fill in code here */
  uint16_t ethernet_type;
  int min_length = ETHERNET_HDR_SIZE;

  /* Check that the packet is large enough to hold an Ethernet header */
  if (len < min_length)
  {
    fprintf(stderr, "insufficient length\n");
    return;
  }

  sr_ethernet_hdr_t *ethernet_hdr;
  ethernet_hdr = (sr_ethernet_hdr_t *)(packet);
  ethernet_type = ethertype(packet);
  
  /* Check IP packets */
  if (ethernet_type == ethertype_ip)
  {
    char *forward_interface;
    struct sr_rt *entry;
    struct sr_arpentry *arp_entry;

    /* Check that the packet is large enough to hold IP header */
    min_length += IP_HDR_SIZE;

    if (len < min_length)
    {
      fprintf(stderr, "insufficient length\n");
      return;
    }

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + ETHERNET_HDR_SIZE);
    uint16_t ip_sum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, IP_HDR_SIZE);
    /* Check sum of IP packet */
    if (ip_sum != ip_hdr->ip_sum)
    {
      printf("cksum invalid\n");
      return;
    }

    ip_hdr->ip_ttl -= 1; 
    
    if (ip_hdr->ip_ttl == 0)
    {
      if (is_if_list(sr, ip_hdr->ip_dst))
      {
        sr_send_icmp_unreachable(sr, packet, interface, PORT_UN_TYPE,
                                 PORT_UN_CODE);
      }
      sr_send_icmp_unreachable(sr, packet, interface, TIME_EXC_TYPE,
                               TIME_EXC_CODE);

      return;
    }

    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, IP_HDR_SIZE);

    /* If the same subnet */
    uint8_t ip_proto = ip_protocol(packet + ETHERNET_HDR_SIZE);
    uint8_t icmp_type;

    if (ip_proto == ip_protocol_icmp)
    {
      min_length += ICMP_HDR_SIZE;
      if (len < min_length)
      {
        return; 
      }
      /* Generating Reply */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + ETHERNET_HDR_SIZE +
                                 IP_HDR_SIZE);
      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + ETHERNET_HDR_SIZE);
      icmp_type = icmp_hdr->icmp_type;
      if (icmp_type == ECHO_TYPE && is_if_list(sr, ip_hdr->ip_dst))
      {
        sr_send_icmp_reply(sr, packet, len, interface);
        return;
      }
    }

    entry = sr->routing_table;
    unsigned long max_prefix = 0;
    struct sr_rt *ans = NULL;

    /* Find ethernet to forward packet */
    while (entry)
    {
      if (and_operator(entry->dest.s_addr, entry->mask) ==
          and_operator(ip_hdr->ip_dst, entry->mask) 
          && (max_prefix <= entry->mask.s_addr))
      {
        max_prefix = entry->mask.s_addr;
        ans = entry;
      }
      entry = entry->next;
    } 
    
    if (ans != NULL)
    {
      forward_interface = ans->interface;
    }
    else
    {
      sr_send_icmp_unreachable(sr, packet, interface, DST_NET_UN_TYPE,
                               DST_NET_UN_CODE);
      return;
    }

    free(entry); 
    arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);

    if (arp_entry)
    {
      struct sr_if *if_walker = sr_get_interface(sr, forward_interface);
      
      memcpy(ethernet_hdr->ether_shost, if_walker->addr, ETHER_ADDR_LEN);
      memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

      /* print_hdrs(packet, len); */
      sr_send_packet(sr, packet, len, forward_interface);
    }
    else
    {
      struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache),
                               ip_hdr->ip_dst, packet, len, forward_interface);
      handle_arpreq(sr, req);
    }
  }
  /* ARP packet */
  else if (ethernet_type == ethertype_arp)
  {
    uint8_t opcode;
    
    /* Check that the packet is large enough to hold ARP header */
    min_length += ARP_HDR_SIZE;

    if (len < ARP_HDR_SIZE)
    {
      return;
    }

    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + ETHERNET_HDR_SIZE);
    opcode = ntohs(arp_hdr->ar_op);

    /* ARP request */
    if (opcode == REQUEST_ARP_OPCODE)
    {
      /* Generating ARP Reply */
      sr_send_arp_reply(sr, packet, len, interface);
    }
    /* ARP reply */
    else if (opcode == REPLY_ARP_OPCODE)
    {
      /* Update ARP Table */
      struct sr_arpreq *req;
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + ETHERNET_HDR_SIZE);

      req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

      if (req)
      {
        struct sr_packet *packets = req->packets;
        while (packets)
        {
          sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)(packets->buf);
          struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache),
                                                             req->ip);

          if (arp_entry)
          {
            struct sr_if *if_walker = sr_get_interface(sr, packets->iface);
            memcpy(ethernet_hdr->ether_shost, if_walker->addr,
                   ETHER_ADDR_LEN );
            memcpy(ethernet_hdr->ether_dhost, arp_entry->mac,
                   ETHER_ADDR_LEN );
            /* print_hdrs(packets->buf, packets->len);  */
            sr_send_packet(sr, packets->buf, packets->len, packets->iface);
          }

          free(arp_entry); 

          packets = packets->next;
        }
        sr_arpreq_destroy(&(sr->cache), req);
      }
    }
  }
  else
  {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethernet_type);
  }
}/* end sr_ForwardPacket */

static uint32_t 
and_operator(uint32_t ip, struct in_addr mask)
{
  return (mask.s_addr & ip);
}

static uint8_t 
is_if_list(struct sr_instance *sr, uint32_t dst_ip)
{
  struct sr_if *if_walker = 0;

  if (sr->if_list == 0)
  {
    return 0;
  }

  if_walker = sr->if_list;

  while (if_walker)
  {
    if (if_walker->ip == dst_ip)
    {
      return 1;
    }
    if_walker = if_walker->next;
  }
  return 0;
}

static void
sr_send_icmp_reply(struct sr_instance *sr, uint8_t *buff,
                   unsigned int len, char *interface)
{
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)(buff);
  struct sr_if *if_walker = sr_get_interface(sr, interface);
  uint32_t ip_src;

  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN );
  memcpy(ethernet_hdr->ether_shost, if_walker->addr, ETHER_ADDR_LEN );

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buff + ETHERNET_HDR_SIZE);

  ip_src = ip_hdr->ip_dst;
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = ip_src;

  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buff + ETHERNET_HDR_SIZE +
                                              IP_HDR_SIZE);
  icmp_hdr->icmp_type = ECHO_REPLY_TYPE;

  sr_send_packet(sr, buff, len, if_walker->name);
}

static void 
sr_send_icmp_unreachable(struct sr_instance *sr, uint8_t *packet, char *iface,
                         uint8_t icmp_type, uint8_t icmp_code)
{
  unsigned int len = ETHERNET_HDR_SIZE + IP_HDR_SIZE + ICMP_T3_HDR_SIZE;
  uint8_t *icmp_unread_packet = calloc(1, len);
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_ethernet_hdr_t 
    *ethernet_icmp_hdr = (sr_ethernet_hdr_t *)icmp_unread_packet;
  struct sr_if *if_walker = sr_get_interface(sr, iface);

  memcpy(ethernet_icmp_hdr->ether_dhost, ethernet_hdr->ether_shost,
         ETHER_ADDR_LEN );
  memcpy(ethernet_icmp_hdr->ether_shost, if_walker->addr, ETHER_ADDR_LEN );
  ethernet_icmp_hdr->ether_type = htons(ethertype_ip);

  sr_ip_hdr_t *packet_ip_hdr =
                         (sr_ip_hdr_t *)(packet + ETHERNET_HDR_SIZE);
  sr_ip_hdr_t *ip_icmp_hdr = (sr_ip_hdr_t *)(icmp_unread_packet + 
                                             ETHERNET_HDR_SIZE);
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_unread_packet + 
                            ETHERNET_HDR_SIZE + IP_HDR_SIZE);

  ip_icmp_hdr->ip_hl = packet_ip_hdr->ip_hl; 
  ip_icmp_hdr->ip_v = packet_ip_hdr->ip_v;
  ip_icmp_hdr->ip_dst = packet_ip_hdr->ip_src;
  ip_icmp_hdr->ip_src = if_walker->ip;
  ip_icmp_hdr->ip_ttl = MAX_TTL;
  ip_icmp_hdr->ip_id = packet_ip_hdr->ip_id;
  ip_icmp_hdr->ip_tos = packet_ip_hdr->ip_tos;
  ip_icmp_hdr->ip_p = ip_protocol_icmp;

  ip_icmp_hdr->ip_len = htons(IP_HDR_SIZE + ICMP_T3_HDR_SIZE);
  ip_icmp_hdr->ip_sum = 0;
  ip_icmp_hdr->ip_sum = cksum(ip_icmp_hdr, IP_HDR_SIZE + ICMP_T3_HDR_SIZE);

  if (icmp_code == PORT_UN_CODE)
  {
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
  }

  if (icmp_type == TIME_EXC_TYPE)
  {
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
  }

  memcpy(icmp_hdr->data, packet_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, ICMP_T3_HDR_SIZE);

  sr_send_packet(sr, icmp_unread_packet, len, iface);

  free(icmp_unread_packet);
}

void 
sr_send_icmp_net_unreachable(struct sr_instance *sr, struct sr_arpreq *req, 
                             uint8_t icmp_code)
{
  struct sr_packet *packets = req->packets;
  
  while (packets)
  {
    uint8_t *buff = packets->buf;
    unsigned int len = ETHERNET_HDR_SIZE + IP_HDR_SIZE + ICMP_T3_HDR_SIZE;
    uint8_t *icmp_unread_packet = calloc(1, len);

    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)(buff);
    sr_ethernet_hdr_t 
      *ethernet_icmp_hdr = (sr_ethernet_hdr_t *)icmp_unread_packet;
    struct sr_if *if_walker = sr_get_interface(sr, packets->iface);
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_unread_packet + 
                              ETHERNET_HDR_SIZE + IP_HDR_SIZE);
     
    memcpy(ethernet_icmp_hdr->ether_dhost, ethernet_hdr->ether_shost,
           ETHER_ADDR_LEN );

    memcpy(ethernet_icmp_hdr->ether_shost, if_walker->addr,
           ETHER_ADDR_LEN );
    ethernet_icmp_hdr->ether_type = htons(ethertype_ip);

    sr_ip_hdr_t *packet_ip_hdr =
                           (sr_ip_hdr_t *)(buff + ETHERNET_HDR_SIZE);
    sr_ip_hdr_t *ip_icmp_hdr = (sr_ip_hdr_t *)(icmp_unread_packet + 
                                               ETHERNET_HDR_SIZE);

    ip_icmp_hdr->ip_hl = packet_ip_hdr->ip_hl; 
    ip_icmp_hdr->ip_v = packet_ip_hdr->ip_v;
    ip_icmp_hdr->ip_dst = packet_ip_hdr->ip_src;
    ip_icmp_hdr->ip_src = if_walker->ip;
    ip_icmp_hdr->ip_ttl = MAX_TTL;
    ip_icmp_hdr->ip_id = packet_ip_hdr->ip_id;
    ip_icmp_hdr->ip_tos = packet_ip_hdr->ip_tos;
    ip_icmp_hdr->ip_p = ip_protocol_icmp;
    ip_icmp_hdr->ip_len = htons(IP_HDR_SIZE + ICMP_T3_HDR_SIZE); 
    ip_icmp_hdr->ip_sum = 0;

    ip_icmp_hdr->ip_sum = cksum(ip_icmp_hdr, IP_HDR_SIZE + ICMP_T3_HDR_SIZE);
  
    icmp_hdr->icmp_type = DST_NET_UN_TYPE;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum = 0;
    memcpy(icmp_hdr->data, ip_icmp_hdr, ICMP_DATA_SIZE);
    icmp_hdr->icmp_sum = cksum(icmp_hdr,
                               ICMP_T3_HDR_SIZE);

    sr_send_packet(sr, icmp_unread_packet, len, packets->iface);

    packets = packets->next;

    free(icmp_unread_packet);
  } 
}

/*-----------------------------------------------------------------------------
 * Method: sr_send_arp_request(struct sr_instance *sr, struct sr_arpreq *req)
 *   
 * Scope: static
 *
 * This method is called each time the router want to send a ARP request  
 * on the interface 
 *---------------------------------------------------------------------------*/
void
sr_send_arp_request(struct sr_instance *sr, struct sr_arpreq *req)
{
  uint8_t *arp_packet = calloc(1, ETHERNET_HDR_SIZE + ARP_HDR_SIZE);
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)(arp_packet);
  struct sr_if *if_walker = sr_get_interface(sr, req->packets->iface);
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(arp_packet +
                                           ETHERNET_HDR_SIZE);
  unsigned int len = ETHERNET_HDR_SIZE + ARP_HDR_SIZE;
  char mac_address[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  memcpy(ethernet_hdr->ether_dhost, mac_address,
         ETHER_ADDR_LEN );
  memcpy(ethernet_hdr->ether_shost, if_walker->addr,
         ETHER_ADDR_LEN );
  ethernet_hdr->ether_type = htons(ethertype_arp);

  arp_hdr->ar_hrd = htons(ARP_HRD);
  arp_hdr->ar_pro = htons(ip_protocol_arp); 
  arp_hdr->ar_hln = (ARP_HLN);
  arp_hdr->ar_pln = (ARP_PLN);
  arp_hdr->ar_op = htons(arp_op_request);
  memcpy(arp_hdr->ar_sha, if_walker->addr, ETHER_ADDR_LEN );
  arp_hdr->ar_sip = (if_walker->ip);
  arp_hdr->ar_tip = req->ip;

  sr_send_packet(sr, arp_packet, len, req->packets->iface); 

  free(arp_packet);
}

static void 
sr_send_arp_reply(struct sr_instance *sr, uint8_t *buff, 
                  unsigned int len, char *interface)
{
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)(buff);
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buff + ETHERNET_HDR_SIZE);
  uint32_t ar_tip;
  struct sr_if *if_walker = sr_get_interface(sr, interface);

  ar_tip = arp_hdr->ar_tip;
  arp_hdr->ar_op = htons(REPLY_ARP_OPCODE);
  arp_hdr->ar_tip = arp_hdr->ar_sip;
  arp_hdr->ar_sip = ar_tip;
  
  memcpy(arp_hdr->ar_tha, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(arp_hdr->ar_sha, if_walker->addr, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_shost, if_walker->addr, ETHER_ADDR_LEN);

  sr_send_packet(sr, buff, len, interface); 
}
