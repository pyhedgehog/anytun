#include <sstream>
#include <iostream>
#include <fstream>
#include <string>

#include "Sockets/Utility.h"
#include "muxSocket.h"

#ifdef SOCKETS_NAMESPACE
using namespace SOCKETS_NAMESPACE;
#endif // SOCKETS_NAMESPACE


MuxSocket::MuxSocket(ISocketHandler& h)
:TcpSocket(h)
{
	SetConnectTimeout(12);
}



void MuxSocket::OnAccept()
{
  std::string filename("testoutput.txt");
  std::ifstream file(filename.c_str());
  if( file.is_open() )
  {
    std::string line;
    while( !file.eof() )
    {
      getline( file, line );
      Send( line + "\n" );
    }
    file.close();
  }
	Send("\n");

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
