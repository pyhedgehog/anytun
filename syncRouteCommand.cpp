#include "syncRouteCommand.h"

SyncRouteCommand::SyncRouteCommand()
{	
}

SyncRouteCommand::SyncRouteCommand( u_int16_t mux )
:mux_(mux)
{	
}

u_int16_t SyncRouteCommand::getMux() const 
{
	return mux_;
}
