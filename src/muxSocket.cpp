#include <sstream>
#include <iostream>
#include <fstream>
#include <string>

#include "anymuxOptions.h"

#include "Sockets/Utility.h"
#include "muxSocket.h"


#ifdef SOCKETS_NAMESPACE
using namespace SOCKETS_NAMESPACE;
#endif // SOCKETS_NAMESPACE


MuxSocket::MuxSocket(ISocketHandler& h) : TcpSocket(h), filename_(gOpt.getFileName())
{
	SetConnectTimeout(12);
}


void MuxSocket::OnAccept()
{
  std::ifstream file(filename_.c_str());
  if( file.is_open() )
  {
    std::string line;
    while( !file.eof() )
    {
      getline( file, line );
      Send( line );
    }
    file.close();
  }

	//TODO Locking here
}

//void StatusSocket::InitSSLServer()
//{
//	InitializeContext("server.pem", "keypwd", SSLv23_method());
//}
//
//
//void StatusSocket::Init()
//{
//	EnableSSL();
//}
