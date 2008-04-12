#include "syncRouteCommand.h"

SyncRouteCommand::SyncRouteCommand()
{	
}

SyncRouteCommand::SyncRouteCommand( const NetworkPrefix & addr )
:addr_(addr)
{	
}


NetworkPrefix SyncRouteCommand::getPrefix() const 
{
	return addr_;
}
