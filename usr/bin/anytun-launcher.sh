#!/bin/sh

NAME="${NAME:-$2}"

DAEMON=/usr/sbin/anytun
ANYTUNCONFIG=/usr/bin/anytun-config
CONTROLDAEMON=/usr/bin/anytun-controld
CONFIG_DIR=/etc/anytun
VARCONFIG_DIR=/run/anytun-controld
VARRUN_DIR=/run/anytun

test -x $DAEMON || exit 0
test -z $NAME && exit 1

start_vpn () {
  if [ -f $CONFIG_DIR/$NAME/config ] ; then
    POSTUP=''
    test -f  $CONFIG_DIR/$NAME/post-up.sh && POSTUP="-x $CONFIG_DIR/$NAME/post-up.sh"
    CHROOTDIR=`grep '^chroot' < $CONFIG_DIR/$NAME/config | sed 's/chroot\s*//'`
    if [ -n "$CHROOTDIR" ] ; then
      test -d $CHROOTDIR || mkdir -p $CHROOTDIR
    fi
    test -d $VARRUN_DIR || mkdir -p $VARRUN_DIR
    DAEMONARG=`sed 's/#.*//' < $CONFIG_DIR/$NAME/config | grep -e '\w' | sed  's/^/--/' | tr '\n' ' '`
    $DAEMON --write-pid $VARRUN_DIR/$NAME.pid $POSTUP $DAEMONOPTS $DAEMONARG
  else
    echo "no config found" >&2
    return 1
  fi
}

start_configd () {
  if [ -d $CONFIG_DIR/$NAME/conf.d ] ; then
    test -d $VARCONFIG_DIR || mkdir -p $VARCONFIG_DIR
    chmod 700 $VARCONFIG_DIR
    rm -f $VARCONFIG_DIR/$NAME 2>/dev/null
    KDPRF=`sed 's/#.*//'  <  $CONFIG_DIR/$NAME/config | grep -e 'kd-prf' | sed  's/^/ --/' | xargs echo`
    for CLIENTNAME in `ls $CONFIG_DIR/$NAME/conf.d`; do
      echo -n " ($CLIENTNAME)"
      DAEMONARG=`sed 's/#.*//'  <  $CONFIG_DIR/$NAME/conf.d/$CLIENTNAME | grep -e '\w' | sed  's/^/ --/' | xargs echo`
      $ANYTUNCONFIG $DAEMONARG $CIPHER $AUTHALGO $KDPRF >> $VARCONFIG_DIR/$NAME
    done
    CONTROLHOST=`sed 's/#.*//'  <  $CONFIG_DIR/$NAME/config | grep -e 'control-host' | sed  's/^/ --/' | xargs echo`
    $CONTROLDAEMON -f $VARCONFIG_DIR/$NAME $DAEMONOPTS $CONTROLHOST \
      --write-pid $VARCONFIG_DIR/$NAME.pid
  else
    echo "no conf.d directory found (maybe $NAME is an anytun client not a server?)" >&2
    return 1
  fi
}

case $1 in
(vpn) start_vpn ;;
(configd) start_configd ;;
(*) exit 2;;
esac
