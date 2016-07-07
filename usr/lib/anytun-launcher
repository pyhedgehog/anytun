#!/bin/sh

NAME="${NAME:-$2}"

DAEMON=/usr/local/sbin/anytun
ANYTUNCONFIG=/usr/local/bin/anytun-config
CONTROLDAEMON=/usr/local/bin/anytun-controld
CONFIG_DIR=/usr/local/etc/anytun
VARRUN_DIR=/run/anytun
VARCONTROL_DIR=/run/anytun-controld

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
    test -d $VARCONTROL_DIR || mkdir -p $VARCONTROL_DIR
    chmod 700 $VARCONTROL_DIR
    rm -f $VARCONTROL_DIR/$NAME 2>/dev/null
    KDPRF=`sed 's/#.*//'  <  $CONFIG_DIR/$NAME/config | grep -e 'kd-prf' | sed  's/^/ --/' | xargs echo`
    for CLIENTNAME in `ls $CONFIG_DIR/$NAME/conf.d`; do
      echo -n " ($CLIENTNAME)"
      DAEMONARG=`sed 's/#.*//'  <  $CONFIG_DIR/$NAME/conf.d/$CLIENTNAME | grep -e '\w' | sed  's/^/ --/' | xargs echo`
      $ANYTUNCONFIG $DAEMONARG $CIPHER $AUTHALGO $KDPRF >> $VARCONTROL_DIR/$NAME
    done
    CONTROLHOST=`sed 's/#.*//'  <  $CONFIG_DIR/$NAME/config | grep -e 'control-host' | sed  's/^/ --/' | xargs echo`
    $CONTROLDAEMON -f $VARCONTROL_DIR/$NAME $DAEMONOPTS $CONTROLHOST \
      --write-pid $VARCONTROL_DIR/$NAME.pid
  else
    echo "no conf.d directory found (maybe $NAME is an anytun client not a server?)" >&2
    return 1
  fi
}

case $1 in
  vpn)
    start_vpn
    ;;
  configd)
    start_configd
    ;;
  *)
    exit 2
    ;;
esac
