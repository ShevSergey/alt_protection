
.PHONY: install

install:
	mkdir -p $(DESTDIR)/usr/share/alt_protection/plugins
	cp -a plugins/*.py $(DESTDIR)/usr/share/alt_protection/plugins
	cp -a *.py $(DESTDIR)/usr/share/alt_protection
	cp altcenter_ru.qm $(DESTDIR)/usr/share/alt_protection/
	install -Dpm0755 alt_protection $(DESTDIR)/usr/bin/alt_protection
