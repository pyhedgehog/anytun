#ifndef _SYNCCOMMAND_H
#define _SYNCCOMMAND_H
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include "connectionList.h"
#include "threadUtils.hpp"
#include "syncConnectionCommand.h"
#include "syncRouteCommand.h"
#include "networkPrefix.h"
#include <string>

class SyncCommand
{
public:
	SyncCommand(ConnectionList & cl );
	SyncCommand(ConnectionList & cl ,u_int16_t mux);
	SyncCommand(NetworkPrefix);
	~SyncCommand();

private:
	SyncCommand(const SyncCommand &);
	SyncConnectionCommand * scc_;
	SyncRouteCommand * src_;
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version)
  {
		std::string syncstr;
		if (scc_)
		{
			syncstr = "connection";
		}
		if ( src_)
		{
			syncstr = "route";
		}
    ar & syncstr;
//		std::cout << "syncstr received " <<syncstr << std::endl;
		if (syncstr == "connection")
			ar & *scc_;
		if (syncstr == "route")
			ar & *src_;
//		std::cout << "syncstr done " <<syncstr << std::endl;
	}
};


#endif // _SYNCCOMMAND_H
