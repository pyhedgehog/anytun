all: manpage

docbook: 	
	asciidoc -b docbook -d manpage anytun.txt

manpage: docbook	
	xmlto man anytun.xml


