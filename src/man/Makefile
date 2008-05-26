all: manpage

anytun.8: anytun.8.txt
	a2x -f manpage anytun.8.txt

anytun-controld.8: anytun-controld.8.txt
	a2x -f manpage anytun-controld.8.txt

anytun-config.8: anytun-config.8.txt
	a2x -f manpage anytun-config.8.txt

anytun-showtables.8: anytun-showtables.8.txt
	a2x -f manpage anytun-showtables.8.txt

anyrtpproxy.8: anyrtpproxy.8.txt
	a2x -f manpage anyrtpproxy.8.txt


manpage: anytun.8 anytun-controld.8 anytun-config.8 anytun-showtables.8 anyrtpproxy.8

clean:
	rm -f anytun.8 anytun.8.xml
	rm -f anytun-controld.8 anytun-controld.8.xml
	rm -f anytun-config.8 anytun-config.8.xml
	rm -f anytun-showtables.8 anytun-showtables.8.xml
	rm -f anyrtpproxy.8 anyrtpproxy.8.xml