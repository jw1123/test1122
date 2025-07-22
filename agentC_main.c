#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "agent_define.h"

// application name
#define APP_NAME        "agentC"
#define CNFG_APP_NAME   "cnfg_agentC"

// agent running flag
static int 	keep_running;
int cnfg_process = 0;

/* define local function */
static void stop_server 	( int  );

/*************************************************************************
 * main
 *
 * Parameters: none
 *
 * Returns: int
 *
 * Description: snmp sub-agent's main function.
 **************************************************************************/
int main ( int argc, char **argv )
{
	int aid;
	char dstr[32], *ap_name;

/*	if( access("/users/tellus/", F_OK) == 0 ) {
 
        #undef IIF_CONF       

        #define IIF_CONF        "/users/tellus/conf/iif.conf"
    }
*/
	ap_name=strrchr(argv[0], '/');
	ap_name++;
	if(!strncmp(ap_name, "cnfg_", 5))
		cnfg_process = 1;

	keep_running = 1;
	
	agent_log("process start : %s", (cnfg_process?CNFG_APP_NAME:APP_NAME));

	// set agent config & mibs directory
	set_configuration_directory((cnfg_process?CNFG_SNMPACONF_DIR:SNMPACONF_DIR));
	printf("%-50s[\x1b[32m  OK\x1b[0m  ]\n","set agentC configuration directory:");
	agent_log("set %s configuration directory:%s",(cnfg_process?"cnfg_agentC":"agentC"),
		   	(cnfg_process?CNFG_SNMPACONF_DIR:SNMPACONF_DIR));
	
	netsnmp_set_mib_directory((cnfg_process?CNFG_SNMPAMIB_DIR:SNMPAMIB_DIR));
	printf("%-50s[\x1b[32m  OK\x1b[0m  ]\n","set private mib directory:");
	agent_log("set private mib directory:%s",(cnfg_process?CNFG_SNMPAMIB_DIR:SNMPAMIB_DIR));

	if(cnfg_process) {
		aid = 0;
	}
	else {
		set_agent_id();
		aid = get_agent_id();
	}
	agent_log("get agent ID = %d",aid);
		
	memset(dstr, 0x00, 32);
	sprintf(dstr, "get agent ID from agentC( %d ):",aid);
	printf("%-50s[\x1b[32m  OK\x1b[0m  ]\n",dstr);
	
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, SUB_AGENT);
	netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,NETSNMP_DS_AGENT_USERID, aid);
	
	netsnmp_enable_subagent();
	printf("%-50s[\x1b[32m  OK\x1b[0m  ]\n","enable agentC's function:");
	agent_log("enable netsnmp subagent function");
	
	/* initialize tcpip, if necessary */
	SOCK_STARTUP;
	
	/* initialize the agent library */
	init_agent((cnfg_process?CNFG_APP_NAME:APP_NAME));
	
	/* read configuration files. */
	init_snmp((cnfg_process?CNFG_APP_NAME:APP_NAME));
	
	/* initialize mib code */
	init_xcnMgmt_mib();
	printf("%-50s[\x1b[32m  OK\x1b[0m  ]\n","initialize xcnMgmt mib:");
	agent_log("initialize xcnMgmt mib");
	
	/* In case we recevie a request to stop (kill -TERM or kill -INT) */
	signal(SIGTERM, stop_server);
	signal(SIGINT, stop_server);
	
	// Send start trap information
	send_easy_trap(SNMP_TRAP_COLDSTART, 0);
	printf("%-50s[\x1b[32m  OK\x1b[0m  ]\n","agentC process started:");

	/* your main loop here... */
	while(keep_running)
	{
		/* if you use select(), see snmp_select_info() in snmp_api(3) */
		/*     --- OR ---  */
		agent_check_and_process(1); /* 0 == don't block */
	}
	
	/* at shutdown time */
	snmp_shutdown((cnfg_process?CNFG_APP_NAME:APP_NAME));
	
	SOCK_CLEANUP;
	printf("%-50s[\x1b[32m  OK\x1b[0m  ]\n","agentC process exit:");
	agent_log("agentC process exit");
	
	return 0;
}

/*************************************************************************
 * stop_server
 *
 * Parameters: none
 *
 * Returns: RETSIGTYPE
 *
 * Description: stop sub-agent.
 **************************************************************************/
static void stop_server(int a)
{
	keep_running = 0;
}

