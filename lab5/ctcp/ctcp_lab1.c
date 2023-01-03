/******************************************************************************
 * ctcp.c
 * ------
 * Implementation of cTCP done here. This is the only file you need to change.
 * Look at the following files for references and useful functions:
 *   - ctcp.h: Headers for this file.
 *   - ctcp_iinked_list.h: Linked list functions for managing a linked list.
 *   - ctcp_sys.h: Connection-related structs and functions, cTCP segment
 *                 definition.
 *   - ctcp_utils.h: Checksum computation, getting the current time.
 *
 *****************************************************************************/

#include "ctcp.h"
#include "ctcp_linked_list.h"
#include "ctcp_sys.h"
#include "ctcp_utils.h"

/**
 * Connection state.
 *
 * Stores per-connection information such as the current sequence number,
 * unacknowledged packets, etc.
 *
 * You should add to this to store other fields you might need.
 */
struct ctcp_state {
  struct ctcp_state *next;  /* Next in linked list */
  struct ctcp_state **prev; /* Prev in linked list */

  conn_t *conn;             /* Connection object -- needed in order to figure
                               out destination when sending */
  linked_list_t *seggreaterments;  /* Linked list of segments sent to this connection.
                               It may be useful to have multiple linked lists
                               for unacknowledged segments, segments that
                               haven't been sent, etc. Lab 1 uses the
                               stop-and-wait protocol and therefore does not
                               necessarily need a linked list. You may remove
                               this if this is the case for you */

  /* FIXME: Add other needed fields. */
  bool waiting_ack;
  char data[MAX_SEG_DATA_SIZE];
  uint16_t num_retransmit;
  uint16_t window;
  uint16_t len;
  uint32_t seqno;
  uint32_t next_seqno;
  uint32_t ackno;
  uint32_t flags;
  uint32_t ackno_checker;
  uint32_t current_seqno_received;
  int rt_timeout;
};

/**
 * Linked list of connection states. Go through this in ctcp_timer() to
 * resubmit segments and tear down connections.
 */
static ctcp_state_t *state_list;
long starting_time; 

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
          code! Helper functions make the code clearer and cleaner. */

/**
 * send_fin(ctcp_state_t *state)
 *
 * Send a fin packet 
 *
 */
static void send_fin(ctcp_state_t *state);

/**
 * send_data(ctcp_state_t *state, char buf[], uint32_t len, bool retransmit)
 *
 * Send a data packet
 *
 */
static void send_data(ctcp_state_t *state, char buf[], uint32_t len, 
                      bool retransmit);

/**
 * send_ack(ctcp_state_t *state, size_t len)
 *
 * Send a ACK packet
 *
 */
static void send_ack(ctcp_state_t *state, size_t len);

ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg) {
  /* Connection could not be established. */
  if (conn == NULL) {
    return NULL;
  }

  /* Established a connection. Create a new state and update the linked list
     of connection states. */
  ctcp_state_t *state = calloc(CTCP_STATE_SIZE, 1);
  state->next = state_list;
  state->prev = &state_list;
  if (state_list)
    state_list->prev = &state->next;
  state_list = state;

  /* Set fields. */
  state->conn = conn;
  /* FIXME: Do any other initialization here. */
  state->seqno = 1;
  state->ackno = 1;
  state->next_seqno = 0;
  state->len = MAX_SEG_DATA_SIZE;
  state->flags = 0; 
  state->window = MAX_SEG_DATA_SIZE;
  state->ackno_checker = 1;
  state->current_seqno_received = 0;
  state->waiting_ack = false;
  state->num_retransmit = 0;
  state->rt_timeout = cfg->rt_timeout;

  return state;
}

static void 
send_fin(ctcp_state_t *state)
{
  ctcp_segment_t *fin_segment;
  
  fin_segment = calloc(CTCP_SEGMENT_SIZE, 1);
  fin_segment->seqno = htonl(state->seqno);
  fin_segment->cksum = 0; 
  fin_segment->ackno = htonl(state->ackno); 
  fin_segment->len = htons(CTCP_SEGMENT_SIZE);
  fin_segment->window = htons(state->window);
  fin_segment->flags |= htonl(FIN);
  
  fin_segment->cksum = cksum(fin_segment, CTCP_SEGMENT_SIZE);
  conn_send(state->conn, fin_segment, CTCP_SEGMENT_SIZE);
  
  free(fin_segment);
}


void ctcp_destroy(ctcp_state_t *state) {
  /* Update linked list. */
  if (state->next)
    state->next->prev = state->prev;

  *state->prev = state->next;
  conn_remove(state->conn);

  /* FIXME: Do any other cleanup here. */

  free(state);
  end_client();
}

static void 
send_data(ctcp_state_t *state, char buf[], uint32_t len, bool retransmit)
{
  starting_time = current_time();
  state->waiting_ack = true;

  ctcp_segment_t *segment;
  int number_data_bytes;
  
  number_data_bytes = len - CTCP_SEGMENT_SIZE;
  segment = calloc(len, 1);
  segment->cksum = 0;
  segment->seqno = htonl(state->seqno);
  segment->ackno = htonl(state->ackno); 
  segment->len = htons(len);
  segment->flags |= htonl(ACK);
  segment->window = htons(state->window);
  memcpy(segment->data, buf, number_data_bytes);
  
  segment->cksum = cksum(segment, len);
  conn_send(state->conn, segment, len); 

  if (!retransmit)
  { 
     state->next_seqno = state->seqno + number_data_bytes;
  }
  
  free(segment);
}

static void 
send_ack(ctcp_state_t *state, size_t len)
{
  ctcp_segment_t *ack_segment;
  uint32_t ackno;

  ackno = len - CTCP_SEGMENT_SIZE;
  state->ackno += ackno;
  
  ack_segment = calloc(CTCP_SEGMENT_SIZE, 1);
  ack_segment->cksum = 0; 
  ack_segment->seqno = htonl(state->seqno);
  ack_segment->ackno = htonl(state->ackno); 
  ack_segment->len = htons(CTCP_SEGMENT_SIZE);
  ack_segment->window = htons(state->window);
  ack_segment->flags |= htonl(ACK);
  
  ack_segment->cksum = cksum(ack_segment, CTCP_SEGMENT_SIZE);
  conn_send(state->conn, ack_segment, CTCP_SEGMENT_SIZE);
  
  free(ack_segment);
}

void ctcp_read(ctcp_state_t *state) {
  /* FIXME */
  int number_data_bytes;
  int leng_of_segment;
  char buf[MAX_SEG_DATA_SIZE];
  if (state->waiting_ack)
  {
    return;
  } 
  number_data_bytes = conn_input(state->conn, buf, MAX_SEG_DATA_SIZE);
  
  if (number_data_bytes == -1)
  {
    send_fin(state);
    return;
  }

  if (number_data_bytes == 0)
  {
    return;
  }

  if (number_data_bytes > 0)
  {
    leng_of_segment = number_data_bytes + CTCP_SEGMENT_SIZE;
    send_data(state, buf, leng_of_segment, false);
    memcpy(state->data, buf, number_data_bytes);
  }
}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {
  /* FIXME */
  uint16_t current_cksum;
  uint32_t buffspace;

  current_cksum = segment->cksum;
  segment->cksum = 0;
  
  if (current_cksum != cksum(segment, len))
  {
    free(segment);
    return;
  }

  segment->cksum = current_cksum;

  if ((segment->flags & htonl(ACK)) && (len == CTCP_SEGMENT_SIZE))
  {
    state->ackno_checker = ntohl(segment->ackno);
    state->waiting_ack = false;
    state->num_retransmit = 0;
    state->seqno = state->next_seqno;
    bzero(state->data, len-CTCP_SEGMENT_SIZE);
    return;
  }

  if (segment->flags & htonl(FIN))
  {
    ctcp_destroy(state);
    return;
  }

  buffspace = conn_bufspace(state->conn);

  if (buffspace < (len-CTCP_SEGMENT_SIZE))
  {
    return;
  }

  if ((state->current_seqno_received == ntohl(segment->seqno)))
  {
    print_hdr_ctcp(segment);
    send_ack(state, len);
    return;
  }

  if (ntohs(segment->len) > len)
  {
    return;
  }

  ctcp_output(state);
  conn_output(state->conn, segment->data, len - CTCP_SEGMENT_SIZE);
  state->current_seqno_received = ntohl(segment->seqno);
  send_ack(state, len);

  free(segment);
}

void ctcp_output(ctcp_state_t *state) {
  /* FIXME */
}

void ctcp_timer() {
  /* FIXME */
  if (state_list)
  {
    int current_timer = current_time();
    int rt_time = current_timer - starting_time;
    if ((state_list->waiting_ack))
    {
      if (rt_time > state_list->rt_timeout)
      {
        if (state_list->num_retransmit < MAX_RETRANSMIT)
        {
          send_data(state_list, state_list->data, (state_list->len), true);
          state_list->num_retransmit += 1;
        }
        else
        {
          ctcp_destroy(state_list);
        }
      }
    }
  }
}
