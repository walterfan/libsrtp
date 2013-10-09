#ifndef _RTP_SESSION_H_
#define _RTP_SESSION_H_

struct srtp_policy_t;

class CRtpSession
{
public:
    CRtpSession(srtp_policy_t* pSrtpPolicy);
    CRtpSession(void);
    ~CRtpSession(void);
private:
    srtp_policy_t* m_pSrtpPolicy;

};

#endif