
void syncOnConnect(SyncTcpConnection * connptr)
{
  ConnectionList & cl_(gConnectionList);
  ConnectionMap::iterator cit = cl_.getBeginUnlocked();
  for (;cit!=cl_.getEndUnlocked();++cit)
  {
    std::ostringstream sout;
    boost::archive::text_oarchive oa(sout);
    const SyncCommand scom(cl_,cit->first);
    oa << scom;
    std::stringstream lengthout;
    lengthout << std::setw(5) << std::setfill('0') << sout.str().size()<< ' ';
    connptr->Send(lengthout.str());
    connptr->Send(sout.str());
  }
  //TODO Locking here
  RoutingMap::iterator it = gRoutingTable.getBeginUnlocked();
  for (;it!=gRoutingTable.getEndUnlocked();++it)
  {
    NetworkPrefix tmp(it->first);
    std::ostringstream sout;
    boost::archive::text_oarchive oa(sout);
    const SyncCommand scom(tmp);
    oa << scom;
    std::stringstream lengthout;
    lengthout << std::setw(5) << std::setfill('0') << sout.str().size()<< ' ';
    connptr->Send(lengthout.str());
    connptr->Send(sout.str());
  }
  //TODO Locking here
  RtpSessionMap::iterator rit = gRtpSessionTable.getBeginUnlocked();
  for (;rit!=gRtpSessionTable.getEndUnlocked();++rit)
  {
    std::ostringstream sout;
    boost::archive::text_oarchive oa(sout);
    const SyncCommand scom(rit->first);
    oa << scom;
    std::stringstream lengthout;
    lengthout << std::setw(5) << std::setfill('0') << sout.str().size()<< ' ';
    connptr->Send(lengthout.str());
    connptr->Send(sout.str());
  }
}

