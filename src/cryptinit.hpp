#ifndef _CRYPTINIT_HPP
#define _CRYPTINIT_HPP
#ifndef NOCRYPT

// boost thread callbacks for libgcrypt
#if defined(BOOST_HAS_PTHREADS)

static int boost_mutex_init(void **priv)
{
  boost::mutex *lock = new boost::mutex();
  if (!lock)
    return ENOMEM;
  *priv = lock;
  return 0;
}

static int boost_mutex_destroy(void **lock)
{
  delete reinterpret_cast<boost::mutex*>(*lock);
  return 0;
}

static int boost_mutex_lock(void **lock)
{
  reinterpret_cast<boost::mutex*>(*lock)->lock();
  return 0;
}

static int boost_mutex_unlock(void **lock)
{
  reinterpret_cast<boost::mutex*>(*lock)->unlock();
  return 0;
}

static struct gcry_thread_cbs gcry_threads_boost =
{ GCRY_THREAD_OPTION_USER, NULL,
  boost_mutex_init, boost_mutex_destroy,
  boost_mutex_lock, boost_mutex_unlock };
#else
#error this libgcrypt thread callbacks only work with pthreads
#endif


#define MIN_GCRYPT_VERSION "1.2.0"

bool initLibGCrypt()
{
  // make libgcrypt thread safe 
  // this must be called before any other libgcrypt call
  gcry_control( GCRYCTL_SET_THREAD_CBS, &gcry_threads_boost );

  // this must be called right after the GCRYCTL_SET_THREAD_CBS command
  // no other function must be called till now
  if( !gcry_check_version( MIN_GCRYPT_VERSION ) ) {
    std::cout << "initLibGCrypt: Invalid Version of libgcrypt, should be >= " << MIN_GCRYPT_VERSION << std::endl;
    return false;
  }

  gcry_error_t err = gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if( err ) {
    char buf[STERROR_TEXT_MAX];
    buf[0] = 0;
    std::cout << "initLibGCrypt: Failed to disable secure memory: " << gpg_strerror_r(err, buf, STERROR_TEXT_MAX) << std::endl;
    return false;
  }

  // Tell Libgcrypt that initialization has completed.
  err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
  if( err ) {
    char buf[STERROR_TEXT_MAX];
    buf[0] = 0;
    std::cout << "initLibGCrypt: Failed to finish initialization: " << gpg_strerror_r(err, buf, STERROR_TEXT_MAX) << std::endl;
    return false;
  }

  cLog.msg(Log::PRIO_NOTICE) << "initLibGCrypt: libgcrypt init finished";
  return true;
}

#endif
#endif

