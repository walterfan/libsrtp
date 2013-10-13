#include <gmock/gmock.h>
#include <gtest/gtest.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>

#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "srtp.h"
#include "srtp_priv.h"

#ifdef __cplusplus
}
#endif

#include "RtpUtil.h"

using namespace std;
using namespace testing;
using ::testing::AtLeast;  

extern unsigned char test_key[30];

debug_module_t mod_driver = {
  0,                  /* debugging is off by default */
  "driver"            /* printable name for module   */
};

err_status_t srtp_test(const srtp_policy_t *policy)
{
  int i;
  srtp_t srtp_sender;
  srtp_t srtp_rcvr;
  err_status_t status = err_status_ok;
  srtp_hdr_t *hdr, *hdr2;
  uint8_t hdr_enc[64];
  uint8_t *pkt_end;
  int msg_len_octets, msg_len_enc;
  int len;
  int tag_length = policy->rtp.auth_tag_len; 
  uint32_t ssrc;
  srtp_policy_t *rcvr_policy;

  debug_print(mod_driver, "srtp create sender session/stream at %d\n", __LINE__);

  err_check(srtp_create(&srtp_sender, policy), __LINE__);

  /* print out policy */
  err_check(srtp_session_print_policy(srtp_sender), __LINE__); 

  /*
   * initialize data buffer, using the ssrc in the policy unless that
   * value is a wildcard, in which case we'll just use an arbitrary
   * one
   */
  if (policy->ssrc.type != ssrc_specific)
    ssrc = 0xdecafbad;
  else
    ssrc = policy->ssrc.value;
  msg_len_octets = 28;
  hdr = srtp_create_test_packet(msg_len_octets, ssrc);

  if (hdr == NULL)
    return err_status_alloc_fail;
  hdr2 = srtp_create_test_packet(msg_len_octets, ssrc);
  if (hdr2 == NULL) {
    free(hdr);
    return err_status_alloc_fail;
  }

  /* set message length */
  len = msg_len_octets;

  debug_print(mod_driver, "before protection:\n%s", 	      
	      srtp_packet_to_string(hdr, len));

#if PRINT_REFERENCE_PACKET
  debug_print(mod_driver, "reference packet before protection:\n%s", 	      
	      octet_string_hex_string((uint8_t *)hdr, len));
#endif

  debug_print(mod_driver, "srtp_protect... at %d\n", __LINE__);

  err_check(srtp_protect(srtp_sender, hdr, &len), __LINE__);

  debug_print(mod_driver, "after protection:\n%s", 	      
	      srtp_packet_to_string(hdr, len));
#if PRINT_REFERENCE_PACKET
  debug_print(mod_driver, "after protection:\n%s", 	      
	      octet_string_hex_string((uint8_t *)hdr, len));
#endif

  /* save protected message and length */
  memcpy(hdr_enc, hdr, len);
  msg_len_enc = len;

  /* 
   * check for overrun of the srtp_protect() function
   *
   * The packet is followed by a value of 0xfffff; if the value of the
   * data following the packet is different, then we know that the
   * protect function is overwriting the end of the packet.
   */
  pkt_end = (uint8_t *)hdr + sizeof(srtp_hdr_t) 
    + msg_len_octets + tag_length;
  for (i = 0; i < 4; i++)
    if (pkt_end[i] != 0xff) {
      fprintf(stdout, "overwrite in srtp_protect() function "
              "(expected %x, found %x in trailing octet %d)\n",
              0xff, ((uint8_t *)hdr)[i], i);
      free(hdr);
      free(hdr2);
      return err_status_algo_fail;
    }  

  /*
   * if the policy includes confidentiality, check that ciphertext is
   * different than plaintext
   * 
   * Note that this check will give false negatives, with some small
   * probability, especially if the packets are short.  For that
   * reason, we skip this check if the plaintext is less than four
   * octets long.
   */
  if ((policy->rtp.sec_serv & sec_serv_conf) && (msg_len_octets >= 4)) {
    printf("testing that ciphertext is distinct from plaintext...");
    status = err_status_algo_fail;
    for (i=12; i < msg_len_octets+12; i++)
      if (((uint8_t *)hdr)[i] != ((uint8_t *)hdr2)[i]) {
	status = err_status_ok;
      }
    if (status) {
      printf("failed\n");
      free(hdr);
      free(hdr2);
      return status;
    }
    printf("passed\n");
  }
  
  /*
   * if the policy uses a 'wildcard' ssrc, then we need to make a copy
   * of the policy that changes the direction to inbound
   *
   * we always copy the policy into the rcvr_policy, since otherwise
   * the compiler would fret about the constness of the policy
   */
  rcvr_policy = (srtp_policy_t*) malloc(sizeof(srtp_policy_t));
  if (rcvr_policy == NULL) {
    free(hdr);
    free(hdr2);
    return err_status_alloc_fail;
  }
  memcpy(rcvr_policy, policy, sizeof(srtp_policy_t));
  if (policy->ssrc.type == ssrc_any_outbound) {
    rcvr_policy->ssrc.type = ssrc_any_inbound;       
  } 
  debug_print(mod_driver, "srtp create receiver session/stream at %d\n", __LINE__);
  err_check(srtp_create(&srtp_rcvr, rcvr_policy), __LINE__);
  debug_print(mod_driver, "srtp_unprotect... at %d\n", __LINE__);
  err_check(srtp_unprotect(srtp_rcvr, hdr, &len), __LINE__);

  debug_print(mod_driver, "after unprotection:\n%s", 	      
	      srtp_packet_to_string(hdr, len));

  /* verify that the unprotected packet matches the origial one */
  for (i=0; i < msg_len_octets; i++)
    if (((uint8_t *)hdr)[i] != ((uint8_t *)hdr2)[i]) {
      fprintf(stdout, "mismatch at octet %d\n", i);
      status = err_status_algo_fail;
    }
  if (status) {
    free(hdr);
    free(hdr2);
    free(rcvr_policy);
    return status;
  }

  /* 
   * if the policy includes authentication, then test for false positives
   */  
  if (policy->rtp.sec_serv & sec_serv_auth) {
    char *data = ((char *)hdr) + 12;
    
    printf("testing for false positives in replay check...");

    /* set message length */
    len = msg_len_enc;

    /* unprotect a second time - should fail with a replay error */
    status = srtp_unprotect(srtp_rcvr, hdr_enc, &len);
    if (status != err_status_replay_fail) {
      printf("failed with error code %d\n", status);
      free(hdr); 
      free(hdr2);
      free(rcvr_policy);
      return status;
    } else {
      printf("passed\n");
    }

    printf("testing for false positives in auth check...");

    /* increment sequence number in header */
    hdr->seq++; 

    /* set message length */
    len = msg_len_octets;

    /* apply protection */
    err_check(srtp_protect(srtp_sender, hdr, &len), __LINE__);
    
    /* flip bits in packet */
    data[0] ^= 0xff;

    /* unprotect, and check for authentication failure */
    status = srtp_unprotect(srtp_rcvr, hdr, &len);
    if (status != err_status_auth_fail) {
      printf("failed\n");
      free(hdr); 
      free(hdr2);
      free(rcvr_policy);
      return status;
    } else {
      printf("passed\n");
    }
            
  }

  err_check(srtp_dealloc(srtp_sender), __LINE__);
  err_check(srtp_dealloc(srtp_rcvr), __LINE__);

  free(hdr);
  free(hdr2);
  free(rcvr_policy);
  return err_status_ok;
}

void CreateTestSrtpPolicy(srtp_policy_t* policy)
{
    //int ignore;
    
    crypto_policy_set_rtp_default(&policy->rtp);
    crypto_policy_set_rtcp_default(&policy->rtcp);
    policy->ssrc.type  = ssrc_specific;
    policy->ssrc.value = 0xdecafbad;
    policy->key  = test_key;
    policy->ekt = NULL;
    policy->window_size = 128;
    policy->allow_repeat_tx = 0;
    policy->next = NULL;
}

TEST(SRTPTest, BasicCase)
{
	printf("--- srtp example --\n");
	
	ASSERT_EQ(0,err_check(srtp_init(), __LINE__));
	ASSERT_EQ(0,err_check(crypto_kernel_load_debug_module(&mod_driver), __LINE__));
	
	err_status_t status = crypto_kernel_set_debug_module("driver", 1);
	status = crypto_kernel_set_debug_module("srtp", 1);
	status = crypto_kernel_set_debug_module("aes icm", 1);
	status = crypto_kernel_set_debug_module("cipher", 1);
	status = crypto_kernel_set_debug_module("auth func", 1);
	status = crypto_kernel_set_debug_module("hmac sha-1", 1);
	
	ASSERT_EQ(0, err_check(status, __LINE__));
	srtp_policy_t policy;
    CreateTestSrtpPolicy(&policy);

	ASSERT_EQ(0,err_check(srtp_test(&policy), __LINE__));
	ASSERT_EQ(0,err_check(srtp_shutdown(), __LINE__));
	printf("--- finish --\n");

}