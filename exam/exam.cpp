// exam.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>

using namespace std;
using namespace testing;
using ::testing::AtLeast;  


int main(int argc, char* argv[])
{
	cout<<"\n---begin---"<<endl; 
	int nTestCase = 2;
	char* ppTestCases[] = {argv[0], "--gtest_filter=SrtpTest*"};//argv;
	testing::InitGoogleMock(&argc, argv);
    RUN_ALL_TESTS();
	
	cout<<"\n---byebye---"<<endl; 
	getchar();
	return 0;
}
