all: manpage

anytun.xml: anytun.txt
	asciidoc -b docbook -d manpage anytun.txt

anytun.8: anytun.xml	
	xmlto man anytun.xml

manpage: anytun.8

clean:
	rm -f anytun.8 anytun.xml
