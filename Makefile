BINARY_ATT=att


# build : will build the app for linux
build:
	@echo "building linux binary started ..."
	GOARCH=amd64 GOOS=linux go build -o ./bin/${BINARY_ATT} cmd/att/main.go
	
	@echo "build done."

# run : builds and run the binary
run: build
	@echo executing the build ${BINARY_ATT} binary
	./bin/${BINARY_ATT}
	@echo "" 

# clean : cleans the ./bin
clean:
	@echo clean started ...
	go clean
	rm ./bin/${BINARY_ATT}

	@echo cleaning done.
