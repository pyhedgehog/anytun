#include "syncRtpCommand.h"

SyncRtpCommand::SyncRtpCommand()
{	
}

SyncRtpCommand::SyncRtpCommand( const std::string & addr )
:callid_(addr)
{	
}


std::string SyncRtpCommand::getCallId() const 
{
	return callid_;
}
