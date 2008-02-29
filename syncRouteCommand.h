#ifndef _SYNCROUTECOMMAND_H
#define _SYNCROUTECOMMAND_H
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "threadUtils.hpp"
#include "networkPrefix.h"
#include "routingTable.h"

class SyncRouteCommand
{
public:
	SyncRouteCommand(const NetworkPrefix & );
	SyncRouteCommand();
	NetworkPrefix getPrefix() const;

private:
	SyncRouteCommand(const SyncRouteCommand &);
	uint16_t count_;
	NetworkPrefix addr_;
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
		Lock lock(gRoutingTable.getMutex());
		ar & addr_;
//		u_int16_t & mux (gRoutingTable.getOrNewRoutingTEUnlocked(addr_));
//		ar & mux;
		ar & gRoutingTable.getOrNewRoutingTEUnlocked(addr_);
	};
};


#endif // _SYNCCOMMAND_H
