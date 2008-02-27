#ifndef _SYNCROUTECOMMAND_H
#define _SYNCROUTECOMMAND_H
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "threadUtils.hpp"

class SyncRouteCommand
{
public:
	SyncRouteCommand(u_int16_t mux);
	SyncRouteCommand();
	u_int16_t getMux() const;

private:
	SyncRouteCommand(const SyncRouteCommand &);
	u_int16_t mux_;
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
		//Lock lock(gRoutingTable.getMutex());
    ar & mux_;
		// ConnectionParam & conn = cl_.getOrNewConnectionUnlocked(mux_);
		// ar & conn;
	}
};


#endif // _SYNCCOMMAND_H
