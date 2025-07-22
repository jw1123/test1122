#include "common.h"
#include <getconfig.h>

extern char nic[][10];
extern char pcap_dump_dir[];

#if 0
 void control_tcpdump(int nic_count, int eid, int pcap_size, int pcap_loop, int tgt_cnt, char tgt_ip[][32], char *host_name, char *date_str, char l4proto)
 {
 	int  i, j, tsize, tloop, tpid, found;

 	char cmdline[256] = {0,};
 	char run_command[256] = {0,};
 	char cmdresult[256] = {0,};
 	char pcap_name[64];
 	char tpath[64] = {0,}, tnic[10], tip[32], tpcapfile[64], proto[10];
 	char killed_proc[64];

 	FILE *fp = NULL;
 	struct stat st = {0};

 	time_t curtime;

 	for(i=0; i<nic_count; i++) {
 		for(j=0; j<tgt_cnt; j++) {
 			found = 0;
			memset(pcap_name, 0, sizeof(pcap_name));
 			//sprintf(pcap_name, "%s_%03d_%s_%s.pcap", host_name, eid, nic[i], (l4proto == PFM_TCP? "TCP":"UDP"), date_str);
 			sprintf(pcap_name, "%s_%03d_%s_%s_%s.pcap", host_name, eid, nic[i], (l4proto == PFM_TCP? "TCP":"UDP"), tgt_ip[j], date_str); // cj
 			memset(cmdline, 0, sizeof(cmdline));
 			if(!strchr(tgt_ip[j], '/')) {
 				sprintf(cmdline, "%s -i %s host %s and %s -s 1600 -Z root -C %d -W %d -w %s",
 								TCPDUMP_APP, nic[i], tgt_ip[j], (l4proto == PFM_TCP? "tcp":"udp"), pcap_size, pcap_loop, pcap_name);
			
 			else {
 				sprintf(cmdline, "%s -i %s net %s and %s -s 1600 -Z root -C %d -W %d -w %s",
 								TCPDUMP_APP, nic[i], tgt_ip[j], (l4proto == PFM_TCP? "tcp":"udp"), pcap_size, pcap_loop, pcap_name);
 			}
 			if(fp = popen(TCPDUMP_CHECK_CMD, "r")) {
 				memset(cmdresult, 0, sizeof(cmdresult));
 				while(fgets(cmdresult, sizeof(cmdresult), fp)) {
 					if( !strstr(cmdresult, nic[i]) || !strstr(cmdresult, "/tcpdump ") ||
 						((l4proto == PFM_TCP) && !strstr(cmdresult, " and tcp -s 1600 -Z root -C ")) ||
 						((l4proto == PFM_UDP) && !strstr(cmdresult, " and udp -s 1600 -Z root -C ")) ) {
 						memset(cmdresult, 0, sizeof(cmdresult));
 						continue;
 					}
					found = 1;
					cmdresult[strlen(cmdresult) - 1] = '\0';
 					tpath[0] = tnic[0] = tip[0] = tpcapfile[0] = proto[0] = '\0';
 					tsize = tloop = tpid = 0;
 					if(!strchr(tgt_ip[j], '/')) {
 						sscanf(cmdresult, "%d %s -i %s host %s and %s -s 1600 -Z root -C %d -W %d -w %s",
 										&tpid, tpath, tnic, tip, proto, &tsize, &tloop, tpcapfile);
					}
 					else {
 						sscanf(cmdresult, "%d %s -i %s net %s and %s -s 1600 -Z root -C %d -W %d -w %s",
 										&tpid, tpath, tnic, tip, proto, &tsize, &tloop, tpcapfile);
 					}
 					// if( (tsize != pcap_size) || (tloop != pcap_loop) ||
 					if(strcmp(tpcapfile, pcap_name) || strcmp(tnic, nic[i]) || strcmp(tip, tgt_ip[j]))
 				   	{
 						writeLogMessage(LOG_SYSTEM, ERR, "pfm", NULL,"[%s] <%s> running: %s",
 							   										__func__, (l4proto == PFM_TCP? "TCP":"UDP"), cmdresult);
 #if 0
 						writeLogMessage(LOG_SYSTEM, ERR, "pfm", NULL,"[%s] <%s> expecting: %s",
 							   										__func__, (l4proto == PFM_TCP? "TCP":"UDP"), cmdline);
 #endif
 						kill(tpid, SIGKILL);
 						sleep(2);
 						memset(killed_proc, 0, sizeof(killed_proc));
 						sprintf(killed_proc, "/proc/%d/status", tpid);
 						if(stat(killed_proc, &st) < 0) {
 							writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> terminate old tcpdump process",
 								   										__func__, (l4proto == PFM_TCP? "TCP":"UDP"));
 							// strcat(cmdline, " &");
 							snprintf(run_command, sizeof(run_command), "cd %s; %s &", pcap_dump_dir, cmdline);
 							system(run_command);
							writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> start tcpdump process: %s",
 								   										__func__, (l4proto == PFM_TCP? "TCP":"UDP"), cmdline);
 						}
 					}
 					else {
 						curtime = time(NULL);
 						if((curtime % 3600) < 5) {
 					 		writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> tcpdump OK: %s",
 							   										__func__, (l4proto == PFM_TCP? "TCP":"UDP"), cmdresult);
						}
 					}
 					memset(cmdresult, 0, sizeof(cmdresult));
 				}
 				pclose(fp);
 				if(!found) {
 					snprintf(run_command, sizeof(run_command), "cd %s; %s &", pcap_dump_dir, cmdline);
 					system(run_command);
 					writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> start tcpdump process: %s",
 								   										__func__, (l4proto == PFM_TCP? "TCP":"UDP"), cmdline);
 				}
			}
 			else {
 				writeLogMessage(LOG_SYSTEM, ERR, "pfm", NULL,"[%s] <%s> process status check failed: %s",
 					   										__func__, (l4proto == PFM_TCP? "TCP":"UDP"), TCPDUMP_CHECK_CMD);
 			}
 		}
 	}
 }
#endif


// 211015 cj 수집하는 ip가 여러개일때 처리하기 위한 함수 수정
// 로직
// 1. 이미 실행중인 tcpdump 프로세스 저장(old_tcpdump_process_array)
// 2. 현재 ipf.rule 룰 설정 파일에 있는 ip와 비교 
// 3-1. old_tcpdump_process_array에 존재하는 ip는 이미 실행중인 프로세스이므로 아무런 조치하지 않고 살려야 되는 프로세스로 체크(alive_process_check_array)
// 3-2. old_tcpdump_process_array에 없는 ip는 ipf.rule 파일에 새로 추가된 ip이므로 새로운 프로세스 실행
// 4. alive_process_check_array에서 살려야되는 프로세스로 체크되지 않은 ip는 프로세스 종료
void control_tcpdump(int nic_count, int eid, int pcap_size, int pcap_loop, int tgt_cnt, char tgt_ip[][32], char *host_name, char *date_str, char l4proto)
{
	int  i, j, k, tsize, tloop, tpid, found;

	char cmdline[256] = {0,};
	char run_command[256] = {0,};
	char cmdresult[256] = {0,};
	char pcap_name[64];
	char tpath[64] = {0,}, tnic[10], tip[32], tpcapfile[64], proto[10];
	char thost_net[10]; // 211015 cj host, net 담기 위한 변수
	char killed_proc[64];
	char old_tcpdump_process_array[MAX_TARGET_IP * 2][256]; // 211015 cj 이미 동작중인 tcpdump 프로세스를 저장하는 배열
	int alive_process_check_array[MAX_TARGET_IP * 2] = {0, }; // 211015 cj old_tcpdump_process_array에서 살려야하는 프로세스 체크하는 배열
	int old_process_cnt = 0; // 211015 cj old_tcpdump_process가 몇개 동작하고 있는지 확인
	FILE *fp = NULL;
	struct stat st = {0};
	time_t curtime;

	char* cj_find = NULL;
	char cj_ip[32] = {0, };

    // 현재 process 상태 체크해서 old_tcpdump_process_array 생성
	if(fp = popen(TCPDUMP_CHECK_CMD, "r"))
	{
		memset(cmdresult, 0, sizeof(cmdresult));
		while(fgets(cmdresult, sizeof(cmdresult), fp))
		{
			if( !strstr(cmdresult, "/tcpdump ") ||
				((l4proto == PFM_TCP) && !strstr(cmdresult, " and tcp -s 1600 -Z root -C ")) ||
				((l4proto == PFM_UDP) && !strstr(cmdresult, " and udp -s 1600 -Z root -C ")) ) 
			{
				memset(cmdresult, 0, sizeof(cmdresult));
				continue;
			}
			else
			{
				if(old_process_cnt >= MAX_TARGET_IP * 2) 
				{
					memset(cmdresult, 0, sizeof(cmdresult));
					continue;
				}
				cmdresult[strlen(cmdresult) - 1] = '\0';
				strcpy(old_tcpdump_process_array[old_process_cnt], cmdresult);
				memset(cmdresult, 0, sizeof(cmdresult));
				
				++old_process_cnt;
			}
		}
		pclose(fp);
	}
	else 
	{
		writeLogMessage(LOG_SYSTEM, ERR, "pfm", NULL,"[%s] <%s> process status check failed: %s", __func__, (l4proto == PFM_TCP? "TCP":"UDP"), TCPDUMP_CHECK_CMD);
	}

	// cj old process 확인용 로그
	for(i = 0; i < old_process_cnt; ++i)
	{
		writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] old_tcpdump_process_array[%d] - %s", __func__, i, old_tcpdump_process_array[i]);
	}

	for(i=0; i<nic_count; i++)
	{
		for(j=0; j<tgt_cnt; j++)
		{
			memset(pcap_name, 0, sizeof(pcap_name));
			//sprintf(pcap_name, "%s_%03d_%s_%s.pcap", host_name, eid, nic[i], (l4proto == PFM_TCP? "TCP":"UDP"), date_str);
			
			memset(cmdline, 0, sizeof(cmdline));

			memset(cj_ip, 0, sizeof(cj_ip));
			strcpy(cj_ip, tgt_ip[j]);
			cj_find = strchr(cj_ip, '/');
			
			if(!cj_find) 
			{
				sprintf(pcap_name, "%s_%03d_%s_%s_%s.pcap", host_name, eid, nic[i], (l4proto == PFM_TCP? "TCP":"UDP"), tgt_ip[j], date_str); // 211015 cj 기존 pcapfile 제목에 타겟 ip추가
				sprintf(cmdline, "%s -i %s host %s and %s -s 1600 -Z root -C %d -W %d -w %s", 
								TCPDUMP_APP, nic[i], tgt_ip[j], (l4proto == PFM_TCP? "tcp":"udp"), pcap_size, pcap_loop, pcap_name);
			}
			else 
			{
				*cj_find = '_';
				sprintf(pcap_name, "%s_%03d_%s_%s_%s.pcap", host_name, eid, nic[i], (l4proto == PFM_TCP? "TCP":"UDP"), cj_ip, date_str); // 211015 cj 기존 pcapfile 제목에 타겟 ip추가
				sprintf(cmdline, "%s -i %s net %s and %s -s 1600 -Z root -C %d -W %d -w %s", 
								TCPDUMP_APP, nic[i], tgt_ip[j], (l4proto == PFM_TCP? "tcp":"udp"), pcap_size, pcap_loop, pcap_name);
			}

			// 첫 시작이면 old_process_cnt가 0일것임 그래서 이땐 바로 실행
			if(old_process_cnt == 0)
			{
				snprintf(run_command, sizeof(run_command), "cd %s; %s &", pcap_dump_dir, cmdline);
				system(run_command);
				writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> start tcpdump process: %s", __func__, (l4proto == PFM_TCP? "TCP":"UDP"), cmdline);
				continue;
			}

			// old_process와 현재 npcap 파일 제목과 target_ip를 비교해서 같은건 그대로 실행
			for(k = 0; k < old_process_cnt; ++k)
			{
				tpath[0] = tnic[0] = tip[0] = tpcapfile[0] = proto[0] = '\0';
				tsize = tloop = tpid = 0;

				if(!strchr(tgt_ip[j], '/')) 
				{
					sscanf(old_tcpdump_process_array[k], "%d %s -i %s host %s and %s -s 1600 -Z root -C %d -W %d -w %s",
									&tpid, tpath, tnic, tip, proto, &tsize, &tloop, tpcapfile);
				}
				else 
				{
					sscanf(old_tcpdump_process_array[k], "%d %s -i %s net %s and %s -s 1600 -Z root -C %d -W %d -w %s",
									&tpid, tpath, tnic, tip, proto, &tsize, &tloop, tpcapfile);
				}

				// 비교하는 if문 pcap 파일 제목이나 target_ip가 같은게 있으면 break;
				if(strcmp(tpcapfile, pcap_name) == 0)
				{
					// 같으면 그대로..
					curtime = time(NULL);
					if((curtime % 3600) < 5) 
					{	
						writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> tcpdump OK: %s",
																__func__, (l4proto == PFM_TCP? "TCP":"UDP"), old_tcpdump_process_array[k]);
					}

					// 살려야 될 프로세스를 체크
					//writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> alive_process_pid - %d", __func__, (l4proto == PFM_TCP? "TCP":"UDP"), tpid);
					alive_process_check_array[k] = 1;
					break;
				}
			}

			// old_tcpdump_process_array 끝까지 확인했는데 같은게 없으면 새로운 프로세스가 설정파일에 추가됐다는 것이라 실행해야 함
			if(k == old_process_cnt)
			{
				snprintf(run_command, sizeof(run_command), "cd %s; %s &", pcap_dump_dir, cmdline);
				system(run_command);
				writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> start tcpdump process: %s",
															__func__, (l4proto == PFM_TCP? "TCP":"UDP"), cmdline);
			}

		}
	}

	// old_tcpdump_process_array alive_process_check_array에 없는 pid는 종료시켜야 함
	for(i = 0; i < old_process_cnt; ++i)
	{
		if(alive_process_check_array[i] == 0)
		{
			tpath[0] = tnic[0] = tip[0] = tpcapfile[0] = proto[0] = thost_net[0] = '\0';
			tsize = tloop = tpid = 0;
			sscanf(old_tcpdump_process_array[i], "%d %s -i %s %s %s and %s -s 1600 -Z root -C %d -W %d -w %s",
									&tpid, tpath, tnic, thost_net, tip, proto, &tsize, &tloop, tpcapfile);
			kill(tpid, SIGKILL);
			sleep(2);
			memset(killed_proc, 0, sizeof(killed_proc));
			sprintf(killed_proc, "/proc/%d/status", tpid);
			if(stat(killed_proc, &st) < 0) 
			{
				writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> terminate old tcpdump process - %s",
															__func__, (l4proto == PFM_TCP? "TCP":"UDP"), old_tcpdump_process_array[i]);
			}
		}
	}
}

int terminate_all(int nic_count, int pcap_size, int pcap_loop, char l4proto)
{
	int  i, j, tsize, tloop, tpid, found = 0;

	char cmdresult[256] = {0,};
	char tpath[64] = {0,}, tnic[10], tip[32], tpcapfile[64], proto[10], thost[10];
	char killed_proc[64];

	FILE *fp = NULL;
	struct stat st = {0};

	for(i=0; i<nic_count; i++) {
		if(fp = popen(TCPDUMP_CHECK_CMD, "r")) {
			memset(cmdresult, 0, sizeof(cmdresult));
			while(fgets(cmdresult, sizeof(cmdresult), fp)) {
				if( !strstr(cmdresult, nic[i]) || !strstr(cmdresult, "/tcpdump ") ||
					((l4proto == PFM_TCP) && !strstr(cmdresult, " and tcp -s 1600 -Z root -C ")) ||
					((l4proto == PFM_UDP) && !strstr(cmdresult, " and udp -s 1600 -Z root -C ")) ) {
					memset(cmdresult, 0, sizeof(cmdresult));
					continue;
				}
				cmdresult[strlen(cmdresult) - 1] = '\0';
				// writeLogMessage(LOG_SYSTEM, ERR, "pfm", NULL,"[%s] <TCP> running:   %s", __func__, cmdresult);
				tpath[0] = tnic[0] = tip[0] = thost[0] = tpcapfile[0] = proto[0] = '\0';
				tsize = tloop = tpid = 0;
				sscanf(cmdresult, "%d %s -i %s %s %s and %s -s 1600 -Z root -C %d -W %d -w %s",
								&tpid, tpath, tnic, thost, tip, proto, &tsize, &tloop, tpcapfile);
				if( (tsize == pcap_size) && (tloop == pcap_loop) && !strcmp(tnic, nic[i]))
			   	{
					writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> running: %s",
						   											__func__, (l4proto == PFM_TCP? "TCP":"UDP"), cmdresult);
					kill(tpid, SIGKILL);
					sleep(2);
					memset(killed_proc, 0, sizeof(killed_proc));
					sprintf(killed_proc, "/proc/%d/status", tpid);
					if(stat(killed_proc, &st) < 0) {
						writeLogMessage(LOG_SYSTEM, INF, "pfm", NULL,"[%s] <%s> terminate tcpdump process",
							   										__func__, (l4proto == PFM_TCP? "TCP":"UDP"));
					}
					found++;
				}
				memset(cmdresult, 0, sizeof(cmdresult));
			}
			pclose(fp);
		}
		else {
			writeLogMessage(LOG_SYSTEM, ERR, "pfm", NULL,"[%s] <%s> process status check failed: %s",
				   										__func__, (l4proto == PFM_TCP? "TCP":"UDP"), TCPDUMP_CHECK_CMD);
		}
	}

	return found;
}

int checkPgmsProc(void)
{
	FILE *fp = NULL;
	char cmdresult[256] = {0,};
	int  proc_cnt = 0;

	if(fp = popen(PGMS_CHECK_CMD, "r")) {
		while(fgets(cmdresult, sizeof(cmdresult), fp)) {
			proc_cnt = atoi(cmdresult);
			break;
		}
		pclose(fp);
	}
	return proc_cnt;
}
