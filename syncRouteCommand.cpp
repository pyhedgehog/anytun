#include "syncRouteCommand.h"

SyncRouteCommand::SyncRouteCommand()
{	
}

SyncRouteCommand::SyncRouteCommand( const NetworkAddress & addr )
:addr_(addr)
{	
}

NetworkAddress SyncRouteCommand::getAddr() const 
{
	return addr_;
}
