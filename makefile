SHELL := /bin/bash

.PHONY: build
build: rfc5424/machine.go rfc5424/builder.go rfc6587/parser.go

rfc5424/machine.go: rfc5424/machine.go.rl rfc5424/rfc5424.rl

rfc5424/builder.go: rfc5424/builder.go.rl rfc5424/rfc5424.rl

rfc5424/builder.go rfc5424/machine.go:
	ragel -Z -G2 -e -o $@ $<
	@gofmt -w -s $@
	@sed -i '/^\/\/line/d' $@
	$(MAKE) file=$@ snake2camel

rfc6587/machine.go: rfc6587/machine.go.rl
	ragel -Z -G2 -e -o $@ $<
	@gofmt -w -s $@
	@sed -i '/^\/\/line/d' $@
	$(MAKE) file=$@ snake2camel

rfc6587/parser.go: rfc6587/parser.go.rl
	ragel -Z -G2 -e -o $@ $<
	@gofmt -w -s $@
	@sed -i '/^\/\/line/d' $@
	$(MAKE) file=$@ snake2camel

.PHONY: snake2camel
snake2camel:
	@awk -i inplace '{ \
	while ( match($$0, /(.*)([a-z])_([a-zA-Z0-9])(.*)/, cap)) \
	$$0 = cap[1] cap[2] toupper(cap[3]) cap[4]; \
	print \
	}' $(file)

.PHONY: bench
bench: rfc5424/*_test.go rfc5424/machine.go
	go test -bench=. -benchmem -benchtime=5s ./...

.PHONY: tests
tests: rfc5424/machine.go rfc5424/builder.go
	go test -race -timeout 10s -coverprofile cover.out -v ./...

docs/rfc6587.dot: rfc6587/parser.go.rl
	ragel -Z -Vp $< -o $@

docs/rfc5424.dot: rfc5424/machine.go.rl rfc5424/rfc5424.rl
	ragel -Z -Vp $< -o $@

docs/rfc5424_pri.dot: rfc5424/machine.go.rl rfc5424/rfc5424.rl
	ragel -Z -Vp -M pri $< -o $@

docs/rfc5424_pri.png: docs/rfc5424_pri.dot
	dot $< -Tpng -o $@

docs/rfc5424_version.dot: rfc5424/machine.go.rl rfc5424/rfc5424.rl
	ragel -Z -Vp -M version $< -o $@

docs/rfc5424_version.png: docs/rfc5424_version.dot
	dot $< -Tpng -o $@

docs/rfc5424_timestamp.dot: rfc5424/machine.go.rl rfc5424/rfc5424.rl
	ragel -Z -Vp -M timestamp $< -o $@

docs/rfc5424_timestamp.png: docs/rfc5424_timestamp.dot
	dot $< -Tpng -o $@

docs/rfc5424_hostname.dot: rfc5424/machine.go.rl rfc5424/rfc5424.rl
	ragel -Z -Vp -M hostname $< -o $@

docs/rfc5424_hostname.png: docs/rfc5424_hostname.dot
	dot $< -Tpng -o $@

docs/rfc5424_appname.dot: rfc5424/machine.go.rl rfc5424/rfc5424.rl
	ragel -Z -Vp -M appname $< -o $@

docs/rfc5424_appname.png: docs/rfc5424_appname.dot
	dot $< -Tpng -o $@

docs/rfc5424_procid.dot: rfc5424/machine.go.rl rfc5424/rfc5424.rl
	ragel -Z -Vp -M procid $< -o $@

docs/rfc5424_procid.png: docs/rfc5424_procid.dot
	dot $< -Tpng -o $@

docs/rfc5424_msgid.dot: rfc5424/machine.go.rl rfc5424/rfc5424.rl
	ragel -Z -Vp -M msgid $< -o $@

docs/rfc5424_msgid.png: docs/rfc5424_msgid.dot
	dot $< -Tpng -o $@

docs/rfc5424_structureddata.dot: rfc5424/machine.go.rl rfc5424/rfc5424.rl
	ragel -Z -Vp -M structureddata $< -o $@

docs/rfc5424_structureddata.png: docs/rfc5424_structureddata.dot
	dot $< -Tpng -o $@

docs/rfc5424_msg.dot: rfc5424/machine.go.rl rfc5424/rfc5424.rl
	ragel -Z -Vp -M msg $< -o $@

docs/rfc5424_msg.png: docs/rfc5424_msg.dot
	dot $< -Tpng -o $@

docs:
	@mkdir -p docs

.PHONY: graph
graph: docs docs/rfc5424.dot docs/rfc5424_pri.png docs/rfc5424_version.png docs/rfc5424_timestamp.png docs/rfc5424_hostname.png docs/rfc5424_appname.png docs/rfc5424_procid.png docs/rfc5424_msgid.png docs/rfc5424_structureddata.png docs/rfc5424_msg.png

.PHONY: clean
clean: rfc5424/machine.go
	@rm -f $?
	@rm -rf docs
