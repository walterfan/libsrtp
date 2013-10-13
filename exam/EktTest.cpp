#include "RtpUtil.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace std;
using namespace testing;
using ::testing::AtLeast;  

extern unsigned char test_key[30];
extern uint8_t ekt_test_key[16];

void CreateEktSrtpPolicy(srtp_policy_t* policy)
{
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

TEST(SRTPTest, EktCase)
{
	printf("--- SRTPTest, EktCase --\n");
	ASSERT_EQ(0,err_check(srtp_init(), __LINE__));

	err_status_t status = crypto_kernel_set_debug_module("srtp", 1);
	ASSERT_EQ(0, err_check(status, __LINE__));
	
	srtp_policy_t policy;
    CreateEktSrtpPolicy(&policy);

	//ASSERT_EQ(0,err_check(srtp_test(&policy), __LINE__));
	ASSERT_EQ(0,err_check(srtp_shutdown(), __LINE__));
}