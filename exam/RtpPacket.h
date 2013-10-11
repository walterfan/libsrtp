#ifndef _RTP_PACKET_H
#define _RTP_PACKET_H

#include "srtp.h"
#include "srtp_priv.h"

class CRtpPacket
{
public:
	CRtpPacket(void);
    CRtpPacket(srtp_hdr_t* pRtpHeader, uint8_t* pMessage);
	virtual ~CRtpPacket(void);
private:
	srtp_hdr_t* m_pRtpHeader;
	uint8_t* m_pPacket;
	uint32_t m_nPacketLen;
};

#endif