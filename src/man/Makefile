all: manpage

anytun.8: anytun.8.txt
	a2x -f manpage anytun.8.txt

anytun-controld.8: anytun-controld.8.txt
	a2x -f manpage anytun-controld.8.txt

anytun-config.8: anytun-config.8.txt
	a2x -f manpage anytun-config.8.txt


manpage: anytun.8 anytun-controld.8 anytun-config.8

clean:
	rm -f anytun.8 anytun.8.xml
	rm -f anytun-controld.8 anytun-controld.8.xml
	rm -f anytun-config.8 anytun-config.8.xml