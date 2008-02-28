#ifndef _SYNCROUTECOMMAND_H
#define _SYNCROUTECOMMAND_H
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "threadUtils.hpp"
#include "networkAddress.h"
#include "routingTable.h"

class SyncRouteCommand
{
public:
	SyncRouteCommand(const NetworkAddress & );
	SyncRouteCommand();
	NetworkAddress getAddr() const;

private:
	SyncRouteCommand(const SyncRouteCommand &);
	NetworkAddress addr_;
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
		Lock lock(gRoutingTable.getMutex());
		ar & addr_;
		u_int16_t & mux = gRoutingTable.getOrNewRoutingTEUnlocked(addr_);
		ar & mux;
	}
};


#endif // _SYNCCOMMAND_H
