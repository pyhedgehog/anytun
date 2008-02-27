#ifndef _SYNCCONNECTIONCOMMAND_H
#define _SYNCCONNECTIONCOMMAND_H
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "connectionList.h"
#include "threadUtils.hpp"

class SyncConnectionCommand
{
public:
	SyncConnectionCommand(ConnectionList & cl );
	SyncConnectionCommand(ConnectionList & cl ,u_int16_t mux);
	u_int16_t getMux() const;

private:
	SyncConnectionCommand(const SyncConnectionCommand &);
	ConnectionList & cl_;
	u_int16_t mux_;
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
		Lock lock(cl_.getMutex());
    ar & mux_;
		ConnectionParam & conn = cl_.getOrNewConnectionUnlocked(mux_);
		ar & conn;
	}
};


#endif // _SYNCCOMMAND_H
