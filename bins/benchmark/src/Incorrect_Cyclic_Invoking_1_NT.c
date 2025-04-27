/*
Commit Number: f569599ae70f0899035f8d5876a7939f629c5976
URL: https://github.com/torvalds/linux/commit/f569599ae70f0899035f8d5876a7939f629c5976
Project Name: linux
License: GPL-2.0
termination: FALSE
*/
#include <stdlib.h>
struct cifsTconInfo{
	int ses;
}cifsTconInfo;
static int cifs_reconnect_tcon(struct cifsTconInfo *tcon, int smb_command);
//1->4
static int smb_init( int smb_command, struct cifsTconInfo *tcon)
{
	int rc = 0;
	rc = cifs_reconnect_tcon(tcon, smb_command);
	return rc;
}
//2->1
int CIFSSMBQFSUnixInfo(const int xid, struct cifsTconInfo *tcon)
{
	int rc = 0;
	rc = smb_init(15, tcon);
	return rc;
}
//3->2
void reset_cifs_unix_caps(int xid, struct cifsTconInfo *tcon)
{
	if (!CIFSSMBQFSUnixInfo(xid, tcon))
	{
		//do something
	}
}
//4->3
static int cifs_reconnect_tcon(struct cifsTconInfo *tcon, int smb_command)
{
	if( !tcon )
		return 0;
	int ses = tcon->ses;
	if( ses )
		reset_cifs_unix_caps(0, tcon);
	return 1;
}
int main(int argc, char* argv[])
{
	struct cifsTconInfo t1;
	struct cifsTconInfo* tcon = &t1;
	tcon->ses = atoi(argv[1]);
	int smb_command = atoi(argv[2]);
	int rc = smb_init(smb_command,tcon);
	return 0;
}
