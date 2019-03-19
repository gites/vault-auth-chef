PROGRAM=vault-auth-chef
BINNAME=$(PROGRAM)
SRCPATH=$(shell pwd)
BUILDDIR=$(SRCPATH)/build
PACKAGE=$(PROGRAM)/chefclient
MAINTEINER=Stan Putrya <root.vagner@gmail.com>
VERSION=$(shell git describe --abbrev=0 --tags)
COMMIT=$(shell git rev-parse --short HEAD)
BUILD_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
BUILD_ORIGIN=$(shell git config remote.origin.url)
LD_FLAGS=-X $(PACKAGE).BuildBranch=$(BUILD_BRANCH) -X $(PACKAGE).GitCommit=$(COMMIT) -X $(PACKAGE).Version=$(TAG) -X $(PACKAGE).BuildOrigin=$(BUILD_ORIGIN)

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
	cd $(SRCPATH)/src/$(PROGRAM) ; GOPATH=$(SRCPATH) go build -ldflags "-s -w $(LD_FLAGS)" -o $(BUILDDIR)/$(BINNAME)

test: prepare
	cd $(SRCPATH)/src/$(PROGRAM)/chefclient ; GOPATH=$(SRCPATH) go test -v

clean:
	@rm -rf $(BUILDDIR)
