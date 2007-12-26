#ifndef _SYNCCOMMAND_H
#define _SYNCCOMMAND_H
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "connectionList.h"
#include "threadUtils.hpp"

class SyncCommand
{
public:
	SyncCommand(ConnectionList & cl );
	SyncCommand(ConnectionList & cl ,u_int16_t mux);
	u_int16_t getMux() const;

private:
	SyncCommand(const SyncCommand &);
  ::Mutex mutex_;
	ConnectionList & cl_;
	u_int16_t mux_;
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
		Lock lock(mutex_);
    ar & mux_;
		ConnectionParam & conn = cl_.getOrNewConnection(mux_);
		ar & conn;
	}
};


#endif // _SYNCSOCKET_H
