#ifndef _RTP_PACKET_H
#define _RTP_PACKET_H

extern struct srtp_hdr_t;

class CRtpPacket
{
public:
	CRtpPacket(void);
	virtual ~CRtpPacket(void);
private:
	srtp_hdr_t* m_pRtpHeader;
	unsigned char* m_pMessage;
	unsigned int m_nPacketLen;
};

#endif