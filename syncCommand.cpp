#include "syncCommand.h"

SyncCommand::SyncCommand(ConnectionList & cl )
{	
	scc_ = new SyncConnectionCommand(cl);
	src_ = new SyncRouteCommand();
}

SyncCommand::SyncCommand(ConnectionList & cl, u_int16_t mux )
{	
	scc_ = new SyncConnectionCommand(cl,mux);
	src_=NULL;
}

SyncCommand::SyncCommand(u_int16_t mux )
{	
	scc_ = NULL;
	src_ = new SyncRouteCommand(mux);
}

SyncCommand::~SyncCommand()
{
	if (scc_)
		delete scc_;
	if (src_)
		delete src_;
}
