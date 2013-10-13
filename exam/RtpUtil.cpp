#include "stdafx.h"
#include "RtpUtil.h"

CRtpUtil::CRtpUtil(void)
{
}


CRtpUtil::~CRtpUtil(void)
{
}

int err_check(err_status_t s, int line) {
  if (s) {
    printf("error (code %d) at %d\n", s, line);
    return 1;
  }
  return 0;
}

srtp_hdr_t *
srtp_create_test_packet(int pkt_octet_len, uint32_t ssrc) {
  int i;
  uint8_t *buffer;
  srtp_hdr_t *hdr;
  int bytes_in_hdr = 12;

  /* allocate memory for test packet */
  hdr = (srtp_hdr_t*) malloc(pkt_octet_len + bytes_in_hdr
	       + SRTP_MAX_TRAILER_LEN + 4);
  if (!hdr)
    return NULL;
  
  hdr->version = 2;              /* RTP version two     */
  hdr->p    = 0;                 /* no padding needed   */
  hdr->x    = 0;                 /* no header extension */
  hdr->cc   = 0;                 /* no CSRCs            */
  hdr->m    = 0;                 /* marker bit          */
  hdr->pt   = 0xf;               /* payload type        */
  hdr->seq  = htons(0x1234);     /* sequence number     */
  hdr->ts   = htonl(0xdecafbad); /* timestamp           */
  hdr->ssrc = htonl(ssrc);       /* synch. source       */

  buffer = (uint8_t *)hdr;
  buffer += bytes_in_hdr;

  /* set RTP data to 0xab */
  for (i=0; i < pkt_octet_len; i++)
    *buffer++ = 0xab;

  /* set post-data value to 0xffff to enable overrun checking */
  for (i=0; i < SRTP_MAX_TRAILER_LEN+4; i++)
    *buffer++ = 0xff;

  return hdr;
}


err_status_t
srtp_session_print_policy(srtp_t srtp) {
  char *serv_descr[4] = {
    "none",
    "confidentiality",
    "authentication",
    "confidentiality and authentication"
  };
  char *direction[3] = {
    "unknown",
    "outbound",
    "inbound"
  };
  srtp_stream_t stream;

  /* sanity checking */
  if (srtp == NULL)
    return err_status_fail;

  /* if there's a template stream, print it out */
  if (srtp->stream_template != NULL) {
    stream = srtp->stream_template;
    printf("# SSRC:          any %s\r\n"
	   "# rtp cipher:    %s\r\n"
	   "# rtp auth:      %s\r\n"
	   "# rtp services:  %s\r\n" 
           "# rtcp cipher:   %s\r\n"
	   "# rtcp auth:     %s\r\n"
	   "# rtcp services: %s\r\n"
	   "# window size:   %lu\r\n"
	   "# tx rtx allowed:%s\r\n",
	   direction[stream->direction],
	   stream->rtp_cipher->type->description,
	   stream->rtp_auth->type->description,
	   serv_descr[stream->rtp_services],
	   stream->rtcp_cipher->type->description,
	   stream->rtcp_auth->type->description,
	   serv_descr[stream->rtcp_services],
	   rdbx_get_window_size(&stream->rtp_rdbx),
	   stream->allow_repeat_tx ? "true" : "false");
  }

  /* loop over streams in session, printing the policy of each */
  stream = srtp->stream_list;
  while (stream != NULL) {
    if (stream->rtp_services > sec_serv_conf_and_auth)
      return err_status_bad_param;
    
    printf("# SSRC:          0x%08x\r\n"
	   "# rtp cipher:    %s\r\n"
	   "# rtp auth:      %s\r\n"
	   "# rtp services:  %s\r\n" 
           "# rtcp cipher:   %s\r\n"
	   "# rtcp auth:     %s\r\n"
	   "# rtcp services: %s\r\n"
	   "# window size:   %lu\r\n"
	   "# tx rtx allowed:%s\r\n",
	   stream->ssrc,
	   stream->rtp_cipher->type->description,
	   stream->rtp_auth->type->description,
	   serv_descr[stream->rtp_services],
	   stream->rtcp_cipher->type->description,
	   stream->rtcp_auth->type->description,
	   serv_descr[stream->rtcp_services],
	   rdbx_get_window_size(&stream->rtp_rdbx),
	   stream->allow_repeat_tx ? "true" : "false");

    /* advance to next stream in the list */
    stream = stream->next;
  } 
  return err_status_ok;
}

err_status_t
srtp_print_policy(const srtp_policy_t *policy) {
  err_status_t status;
  srtp_t session;

  status = srtp_create(&session, policy);
  if (status)
    return status;
  status = srtp_session_print_policy(session);
  if (status)
    return status;
  status = srtp_dealloc(session);
  if (status)
    return status;
  return err_status_ok;
}

/* 
 * srtp_print_packet(...) is for debugging only 
 * it prints an RTP packet to the stdout
 *
 * note that this function is *not* threadsafe
 */

#include <stdio.h>

#define MTU 2048

char packet_string[MTU];

char *
srtp_packet_to_string(srtp_hdr_t *hdr, int pkt_octet_len) {
  int octets_in_rtp_header = 12;
  uint8_t *data = ((uint8_t *)hdr)+octets_in_rtp_header;
  int hex_len = pkt_octet_len-octets_in_rtp_header;

  /* sanity checking */
  if ((hdr == NULL) || (pkt_octet_len > MTU))
    return NULL;

  /* write packet into string */
  sprintf(packet_string, 
	  "(s)rtp packet: {\n"
	  "   version:\t%d\n" 
	  "   p:\t\t%d\n"     
	  "   x:\t\t%d\n"     
	  "   cc:\t\t%d\n"    
	  "   m:\t\t%d\n"     
	  "   pt:\t\t%x\n"    
	  "   seq:\t\t%x\n"   
	  "   ts:\t\t%x\n"    
	  "   ssrc:\t%x\n"    
	  "   data:\t%s\n"    
	  "} (%d octets in total)\n", 
	  hdr->version,  
	  hdr->p,	       
	  hdr->x,	       
	  hdr->cc,       
	  hdr->m,	       
	  hdr->pt,       
	  hdr->seq,      
	  hdr->ts,       
	  hdr->ssrc,      
  	  octet_string_hex_string(data, hex_len),
	  pkt_octet_len);

  return packet_string;
}


/*
 * srtp_validate() verifies the correctness of libsrtp by comparing
 * some computed packets against some pre-computed reference values.
 * These packets were made with the default SRTP policy.
 */




/*
 * srtp policy definitions - these definitions are used above
 */

unsigned char test_key[30] = {
    0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
    0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
    0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
    0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
};


const srtp_policy_t default_policy = {
  { ssrc_any_outbound, 0 },  /* SSRC                           */
  {                      /* SRTP policy                    */                  
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    16,                     /* auth key length in octets   */
    10,                     /* auth tag length in octets   */
    sec_serv_conf_and_auth  /* security services flag      */
  },
  {                      /* SRTCP policy                   */
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    16,                     /* auth key length in octets   */
    10,                     /* auth tag length in octets   */
    sec_serv_conf_and_auth  /* security services flag      */
  },
  test_key,
  NULL,        /* indicates that EKT is not in use */
  128,         /* replay window size */
  0,           /* retransmission not allowed */
  NULL
};

const srtp_policy_t aes_tmmh_policy = {
  { ssrc_any_outbound, 0 },     /* SSRC                        */
  { 
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    UST_TMMHv2,             /* authentication func type    */
    94,                     /* auth key length in octets   */
    4,                      /* auth tag length in octets   */
    sec_serv_conf_and_auth  /* security services flag      */
  },
  { 
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    UST_TMMHv2,             /* authentication func type    */
    94,                     /* auth key length in octets   */
    4,                      /* auth tag length in octets   */
    sec_serv_conf_and_auth  /* security services flag      */
  },
  test_key,
  NULL,        /* indicates that EKT is not in use */
  128,         /* replay window size */
  0,           /* retransmission not allowed */
  NULL
};

const srtp_policy_t tmmh_only_policy = {
  { ssrc_any_outbound, 0 },     /* SSRC                        */
  {
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    UST_TMMHv2,             /* authentication func type    */
    94,                     /* auth key length in octets   */
    4,                      /* auth tag length in octets   */
    sec_serv_auth           /* security services flag      */
  },
  {
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    UST_TMMHv2,             /* authentication func type    */
    94,                     /* auth key length in octets   */
    4,                      /* auth tag length in octets   */
    sec_serv_auth           /* security services flag      */
  },
  test_key,
  NULL,        /* indicates that EKT is not in use */
  128,         /* replay window size */
  0,           /* retransmission not allowed */
  NULL
};

const srtp_policy_t aes_only_policy = {
  { ssrc_any_outbound, 0 },     /* SSRC                        */ 
  {
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    NULL_AUTH,              /* authentication func type    */
    0,                      /* auth key length in octets   */
    0,                      /* auth tag length in octets   */
    sec_serv_conf           /* security services flag      */
  },
  {
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    NULL_AUTH,              /* authentication func type    */
    0,                      /* auth key length in octets   */
    0,                      /* auth tag length in octets   */
    sec_serv_conf           /* security services flag      */
  },
  test_key,
  NULL,        /* indicates that EKT is not in use */
  128,         /* replay window size */
  0,           /* retransmission not allowed */
  NULL
};

const srtp_policy_t hmac_only_policy = {
  { ssrc_any_outbound, 0 },     /* SSRC                        */
  {
    NULL_CIPHER,            /* cipher type                 */
    0,                      /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    20,                     /* auth key length in octets   */
    4,                      /* auth tag length in octets   */
    sec_serv_auth           /* security services flag      */
  },  
  {
    NULL_CIPHER,            /* cipher type                 */
    0,                      /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    20,                     /* auth key length in octets   */
    4,                      /* auth tag length in octets   */
    sec_serv_auth           /* security services flag      */
  },
  test_key,
  NULL,        /* indicates that EKT is not in use */
  128,         /* replay window size */
  0,           /* retransmission not allowed */
  NULL
};

const srtp_policy_t null_policy = {
  { ssrc_any_outbound, 0 },     /* SSRC                        */ 
  {
    NULL_CIPHER,            /* cipher type                 */
    0,                      /* cipher key length in octets */
    NULL_AUTH,              /* authentication func type    */
    0,                      /* auth key length in octets   */
    0,                      /* auth tag length in octets   */
    sec_serv_none           /* security services flag      */  
  },
  {
    NULL_CIPHER,            /* cipher type                 */
    0,                      /* cipher key length in octets */
    NULL_AUTH,              /* authentication func type    */
    0,                      /* auth key length in octets   */
    0,                      /* auth tag length in octets   */
    sec_serv_none           /* security services flag      */  
  },
  test_key,
  NULL,        /* indicates that EKT is not in use */
  128,         /* replay window size */
  0,           /* retransmission not allowed */
  NULL
};

unsigned char test_256_key[46] = {
	0xf0, 0xf0, 0x49, 0x14, 0xb5, 0x13, 0xf2, 0x76,
	0x3a, 0x1b, 0x1f, 0xa1, 0x30, 0xf1, 0x0e, 0x29,
	0x98, 0xf6, 0xf6, 0xe4, 0x3e, 0x43, 0x09, 0xd1,
	0xe6, 0x22, 0xa0, 0xe3, 0x32, 0xb9, 0xf1, 0xb6,

	0x3b, 0x04, 0x80, 0x3d, 0xe5, 0x1e, 0xe7, 0xc9,
	0x64, 0x23, 0xab, 0x5b, 0x78, 0xd2
};

const srtp_policy_t aes_256_hmac_policy = {
  { ssrc_any_outbound, 0 },  /* SSRC                           */
  {                      /* SRTP policy                    */                  
    AES_ICM,                /* cipher type                 */
    46,                     /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    20,                     /* auth key length in octets   */
    10,                     /* auth tag length in octets   */
    sec_serv_conf_and_auth  /* security services flag      */
  },
  {                      /* SRTCP policy                   */
    AES_ICM,                /* cipher type                 */
    46,                     /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    20,                     /* auth key length in octets   */
    10,                     /* auth tag length in octets   */
    sec_serv_conf_and_auth  /* security services flag      */
  },
  test_256_key,
  NULL,        /* indicates that EKT is not in use */
  128,         /* replay window size */
  0,           /* retransmission not allowed */
  NULL
};

uint8_t ekt_test_key[16] = {
  0x77, 0x26, 0x9d, 0xac, 0x16, 0xa3, 0x28, 0xca, 
  0x8e, 0xc9, 0x68, 0x4b, 0xcc, 0xc4, 0xd2, 0x1b
};

#include "ekt.h"

ekt_policy_ctx_t ekt_test_policy = {
  0xa5a5,                   /* SPI */
  EKT_CIPHER_AES_128_ECB,
  ekt_test_key,
  NULL
};

const srtp_policy_t hmac_only_with_ekt_policy = {
  { ssrc_any_outbound, 0 },     /* SSRC                        */
  {
    NULL_CIPHER,            /* cipher type                 */
    0,                      /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    20,                     /* auth key length in octets   */
    4,                      /* auth tag length in octets   */
    sec_serv_auth           /* security services flag      */
  },  
  {
    NULL_CIPHER,            /* cipher type                 */
    0,                      /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    20,                     /* auth key length in octets   */
    4,                      /* auth tag length in octets   */
    sec_serv_auth           /* security services flag      */
  },
  test_key,
  &ekt_test_policy,        /* indicates that EKT is not in use */
  128,                     /* replay window size */
  0,                       /* retransmission not allowed */
  NULL
};


/*
 * an array of pointers to the policies listed above
 *
 * This array is used to test various aspects of libSRTP for
 * different cryptographic policies.  The order of the elements
 * matters - the timing test generates output that can be used
 * in a plot (see the gnuplot script file 'timing').  If you 
 * add to this list, you should do it at the end.
 */

#define USE_TMMH 0

const srtp_policy_t *
policy_array[] = {
  &hmac_only_policy,
#if USE_TMMH
  &tmmh_only_policy,
#endif
  &aes_only_policy,
#if USE_TMMH
  &aes_tmmh_policy,
#endif
  &default_policy,
  &null_policy,
  &aes_256_hmac_policy,
  &hmac_only_with_ekt_policy,
  NULL
};

const srtp_policy_t wildcard_policy = {
  { ssrc_any_outbound, 0 }, /* SSRC                        */
  {                      /* SRTP policy                    */                  
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    16,                     /* auth key length in octets   */
    10,                     /* auth tag length in octets   */
    sec_serv_conf_and_auth  /* security services flag      */
  },
  {                      /* SRTCP policy                   */
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    16,                     /* auth key length in octets   */
    10,                     /* auth tag length in octets   */
    sec_serv_conf_and_auth  /* security services flag      */
  },
  test_key,
  NULL,
  128,                   /* replay window size */
  0,                     /* retransmission not allowed */
  NULL
};
