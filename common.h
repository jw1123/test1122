#ifndef __COMMON_H__
#define __COMMON_H__

#include "libutil.h"

#define VERSION "1.0.0.0"
#define MAX_STRBUFF 512
#define MAX_LINEBUFF (MAX_STRBUFF * 2)

#define ERROR -1
#define TRUE  1
#define FALSE 0

#define PFM_TCP 6
#define PFM_UDP 17

#define MAX_BUFFSIZE    256
#define MAX_TARGET_IP   10

#define MAX_MQSIZE      160
#define PFM_MSGKEY      0x4754
#define PCAP_PFM        0x6002
#define PREFIX_SIZE     32
#define MAX_HASH_SIZE   256

#define UTM_MODULE_NAME "transmit"	// java

#define PCAP_SAVE_DIR	DATA_PCAP_DIR		// "/data/pcap"
#define PCAP_HOME_DIR	"/data"

#define PFM_HOME		"/users/pfm"
#define PFM_LOGDIR		PFM_HOME/"/log"
#define TCPDUMP_APP 	"/usr/sbin/tcpdump"
#define PGMS_CONF_FILE	"/users/pgms/tellus/conf/pgms.conf"
#define IIF_CONF_FILE	"/users/pgms/tellus/conf/iif.conf"
#define PFM_CONF_FILE	PFM_HOME"/conf/pfm.conf"
// #define IPF_RULE_FILE	"/users/pgms/tellus/conf/ipf.rule"

#define TCPDUMP_CHECK_CMD	"ps -eo pid,command"
#define PGMS_CHECK_CMD		"ps -eo comm |egrep 'dpdctrl|voipctrl' |grep -v grep |wc -l"

char warrant_no[MAX_BUFFSIZE];

#endif	// __COMMON_H__
