@rem Point to point example
@rem please make sure to keep the remote-host parameter, even if it's wrong, to avoid problems with windows firewall
@rem anytun --interface 0.0.0.0 --passphrase lala --type tap --ifconfig 5.0.225.2/8 --remote-host 1.1.1.2 --remote-port 4444
anytun --interface 0.0.0.0 --passphrase lala --type tap --ifconfig 5.0.225.1/8 --remote-host 1.1.1.1 --remote-port 4444 --role right
pause 