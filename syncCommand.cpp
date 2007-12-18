#include "syncCommand.h"

SyncCommand::SyncCommand(ConnectionList & cl )
:cl_(cl)
{	
}

SyncCommand::SyncCommand(ConnectionList & cl, u_int16_t mux )
:cl_(cl),mux_(mux)
{	
}

u_int16_t SyncCommand::getMux() const 
{
	return mux_;
}
