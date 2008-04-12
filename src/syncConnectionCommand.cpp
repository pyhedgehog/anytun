#include "syncConnectionCommand.h"

SyncConnectionCommand::SyncConnectionCommand(ConnectionList & cl )
:cl_(cl)
{	
}

SyncConnectionCommand::SyncConnectionCommand(ConnectionList & cl, u_int16_t mux )
:cl_(cl),mux_(mux)
{	
}

u_int16_t SyncConnectionCommand::getMux() const 
{
	return mux_;
}
