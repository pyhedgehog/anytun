#include "syncCommand.h"

SyncCommand::SyncCommand(ConnectionList & cl )
{	
	scc_ = new SyncConnectionCommand(cl);
	src_ = new SyncRouteCommand();
	srtpc_ = new SyncRtpCommand();
}

SyncCommand::SyncCommand(ConnectionList & cl, u_int16_t mux )
{	
	scc_ = new SyncConnectionCommand(cl,mux);
	src_=NULL;
	srtpc_=NULL;
}

SyncCommand::SyncCommand(NetworkPrefix np )
{	
	scc_ = NULL;
	src_ = new SyncRouteCommand(np);
	srtpc_=NULL;
}

SyncCommand::SyncCommand(const std::string & callid )
{	
	scc_ = NULL;
	src_ = NULL;
	srtpc_= new SyncRtpCommand(callid);
}

SyncCommand::~SyncCommand()
{
	if (scc_)
		delete scc_;
	if (src_)
		delete src_;
	if (srtpc_)
		delete srtpc_;
}
