#ifndef _SYNCRTPCOMMAND_H
#define _SYNCRTPCOMMAND_H
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "threadUtils.hpp"
#include "rtpSessionTable.h"

class SyncRtpCommand
{
public:
	SyncRtpCommand(const std::string & );
	SyncRtpCommand();
	std::string getCallId() const;

private:
	SyncRtpCommand(const SyncRtpCommand &);
	std::string callid_;
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
		Lock lock(gRtpSessionTable.getMutex());
		ar & callid_;
		ar & gRtpSessionTable.getOrNewSessionUnlocked(callid_);
	};
};


#endif // _SYNCCOMMAND_H
