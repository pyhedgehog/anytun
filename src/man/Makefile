all: manpage

docbook: anytun.txt
	asciidoc -b docbook -d manpage anytun.txt

manpage: docbook	
	xmlto man anytun.xml

clean:
	rm -f anytun.8 anytun.xml
