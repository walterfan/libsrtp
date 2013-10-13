#ifndef _RTP_UTIL_H_
#define _RTP_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif
#include "srtp.h"
#include "srtp_priv.h"
#ifdef __cplusplus
}
#endif


class CRtpUtil
{
public:
	CRtpUtil(void);
	~CRtpUtil(void);

};

int err_check(err_status_t s, int line);

char* srtp_packet_to_string(srtp_hdr_t *hdr, int pkt_octet_len);

err_status_t srtp_session_print_policy(srtp_t srtp);

srtp_hdr_t * srtp_create_test_packet(int pkt_octet_len, uint32_t ssrc);

#endif