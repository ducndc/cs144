#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */
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

  nat->mappings = calloc(1, sizeof(struct sr_nat_mapping));
  /* Initialize any variables here */

  return success;
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping *mapping = nat->mappings;

  while (mapping)
  {
    struct sr_nat_mapping *temp = mapping;
    mapping = temp->next;
    free(mapping);
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;

  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    struct sr_nat_mapping *mapping = nat->mappings;
    struct sr_nat_mapping *temp = NULL;

    /* handle ICMP query mapping */
    if (mapping->type == nat_mapping_icmp && mapping->last_updated != 0 &&
        (curtime - mapping->last_updated) > g_ICMP_query_timeout_interval)
    {
      temp = mapping;
      nat->mappings = mapping->next;
      free(temp);
    }
    if (mapping->type == nat_mapping_tcp && mapping->last_updated != 0 &&
       (curtime - mapping->last_updated) > g_TCP_established_idle_timeout)
    {
      temp = mapping;
      nat->mappings = mapping->next;
      free(temp);
    }

    else
    {
      mapping = mapping->next;
      while (mapping != NULL)
      {
        if (mapping->type == nat_mapping_icmp && mapping->last_updated != 0 &&
            (curtime - mapping->last_updated) > g_ICMP_query_timeout_interval)
        {
          temp = mapping;
          mapping = mapping->next;
          free(temp);
          continue;
        }
        if (mapping->type == nat_mapping_tcp && mapping->last_updated != 0 &&
            (curtime - mapping->last_updated) > g_TCP_established_idle_timeout)
        {
          temp = mapping;
          mapping = mapping->next;
          free(temp);
          continue;
        }
        else
        {
          mapping = mapping->next;
        }
     }
    }
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
  struct sr_nat_mapping *mapping = nat->mappings;

  while (mapping)
  {
    if (mapping->aux_ext == aux_ext &&
        mapping->type == type) 
    {
      copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
      mapping->last_updated = time(NULL);
      break;
    }
    mapping = mapping->next;
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
  struct sr_nat_mapping *mapping = nat->mappings;

  while (mapping)
  {
    if (mapping->ip_int == ip_int && mapping->aux_int == aux_int &&
        mapping->type == type)
    {
      copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
      mapping->last_updated = time(NULL);
      break;
    }
    mapping = mapping->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));
  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *copy = calloc(1, sizeof(struct sr_nat_mapping));
  mapping = calloc(1, sizeof(struct sr_nat_mapping));

  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->ip_ext =  0;
  mapping->aux_int = aux_int;
  if (type == nat_mapping_icmp)
  {
    mapping->aux_ext = htons(g_ICMP_nat_port++);
    mapping->conns = NULL;
  }
  else if (type == nat_mapping_tcp)
  {
    mapping->aux_ext = htons(g_TCP_nat_port++);
    mapping->conns = NULL;
  }
  mapping->last_updated = time(NULL);

  mapping->next = nat->mappings;
  nat->mappings = mapping;

  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
