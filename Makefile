PROGRAM=vault-auth-chef
BINNAME=$(PROGRAM)
SRCPATH=$(shell pwd)
BUILDDIR=$(SRCPATH)/build
MAINTEINER=Stan Putrya <root.vagner@gmail.com>
VERSION=$(shell git describe --abbrev=0 --tags)

.PHONY: all clean systemd prepare package

all: deps build

tools:
	go get -u github.com/kardianos/govendor

prepare: clean
	@mkdir $(BUILDDIR)

deps: tools
	cd $(SRCPATH)/src/$(PROGRAM) ;	GOPATH=$(SRCPATH) govendor init 
	cd $(SRCPATH)/src/$(PROGRAM) ;	GOPATH=$(SRCPATH) govendor fetch +missing 

build: prepare
	cd $(SRCPATH)/src/$(PROGRAM) ; GOPATH=$(SRCPATH) go build -o $(BUILDDIR)/$(BINNAME)

test: prepare
	cd $(SRCPATH)/src/$(PROGRAM)/chefclient ; GOPATH=$(SRCPATH) go test -v

clean:
	@rm -rf $(BUILDDIR)
