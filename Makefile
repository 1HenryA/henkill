PROGRAM_NAME=henkill
VERSION=1.0

DOCS_DIR=/usr/share/doc
PROGRAM_DIR=/usr/bin

install:
	install -Dm644 README.md $(DOCS_DIR)/$(PROGRAM_NAME)/README.md
	install -Dm755 henkill.sh $(PROGRAM_DIR)/$(PROGRAM_NAME)

uninstall:
	rm -Rf $(DOCS_DIR)/$(PROGRAM_NAME)
	rm -Rf $(PROGRAM_DIR)/$(PROGRAM_NAME)

