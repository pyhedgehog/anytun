/*
 *	anytun
 *
 *	The secure anycast tunneling protocol (satp) defines a protocol used
 *	for communication between any combination of unicast and anycast
 *	tunnel endpoints.	 It has less protocol overhead than IPSec in Tunnel
 *	mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *	ethernet, ip, arp ...). satp directly includes cryptography and
 *	message authentication based on the methodes used by SRTP.	It is
 *	intended to deliver a generic, scaleable and secure solution for
 *	tunneling and relaying of packets of any protocol.
 *
 *
 *	Copyright (C) 2007-2008 Othmar Gsenger, Erwin Nindl, 
 *													Christian Pointner <satp@wirdorange.org>
 *
 *	This file is part of Anytun.
 *
 *	Anytun is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 3 as
 *	published by the Free Software Foundation.
 *
 *	Anytun is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with anytun.	If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <string>
#include <boost/system/system_error.hpp>
#include "log.h"

#include "threadUtils.hpp"

Log* Log::inst = NULL;
Mutex Log::instMutex;
Log& cLog = Log::instance();

#ifndef NOCRYPT
#ifndef USE_SSL_CRYPTO
std::ostream& operator<<(std::ostream& stream, LogGpgError const& value) 
{
	char buf[STERROR_TEXT_MAX];
	buf[0] = 0;
	gpg_strerror_r(value.err_, buf, STERROR_TEXT_MAX);
	return stream << buf;
}
#endif
#endif
std::ostream& operator<<(std::ostream& stream, LogErrno const& value)
{
	boost::system::system_error err(boost::system::error_code(value.err_,boost::system::get_system_category()));
//	boost::system::system_error err(boost::system::error_code(value.err_,boost::system::get_posix_category()));
	return stream << err.what();
}

LogStringBuilder::LogStringBuilder(LogStringBuilder const& src) : log(src.log), prio(src.prio) 
{
	stream << src.stream.str();
}

LogStringBuilder::LogStringBuilder(Log& l, int p) : log(l), prio(p) 
{
			// do something on the start of the line.
}

LogStringBuilder::~LogStringBuilder() 
{
	Lock lock(log.mutex);
#ifndef NOSYSLOG
	syslog(prio | log.getFacility(), "%s", stream.str().c_str());	 
#endif
#ifdef LOGSTDOUT
	std::cout << "LOG-" << Log::prioToString(prio) << ": " << stream.str() << std::endl;
#endif
}

Log& Log::instance()
{
	Lock lock(instMutex);
	static instanceCleaner c;
	if(!inst)
		inst = new Log();
	
	return *inst;
}

Log::Log()
{
	facility = FAC_DAEMON;
	logName = "anytun";
	open();
}

Log::~Log()
{
#ifndef NOSYSLOG
	closelog();
#endif
}

#ifdef NOSYSLOG
std::string Log::prioToString(int prio)
{
	switch(prio) {
	case PRIO_EMERG: return "EMERG";
	case PRIO_ALERT: return "ALERT";
	case PRIO_CRIT: return "CRIT";
	case PRIO_ERR: return "ERR";
	case PRIO_WARNING: return "WARNING";
	case PRIO_NOTICE: return "NOTICE";
	case PRIO_INFO: return "INFO";
	case PRIO_DEBUG: return "DEBUG";
	default: return "UNKNOWN";
	}
}
#endif

void Log::open()
{
#ifndef NOSYSLOG
	openlog(logName.c_str(), LOG_PID, facility);
#endif
}

Log& Log::setLogName(std::string newLogName)
{
	logName = newLogName;
	open();
	return *this;
}

Log& Log::setFacility(int newFacility)
{
	facility = newFacility;
	open();
	return *this;
}
