%.html : %.xml
	xml2rfc $^ $@
%.txt : %.xml
	xml2rfc $^ $@

PAPERS = draft-gsenger-secure-anycast-tunneling-protocol-02.html \
		 draft-gsenger-secure-anycast-tunneling-protocol-02.txt

all: doc
doc: $(PAPERS)

clean:
	rm -f $(PAPERS)
