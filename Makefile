.PHONY: build-x86 build-arm64 push all dev-backend dev-frontend

# Build Vars
IMAGENAME=nicolaka/netshoot
VERSION=0.1


.DEFAULT_GOAL := all

build-x86:
	    @docker build --platform linux/amd64 -t ${IMAGENAME}:${VERSION} .
build-arm64:
		@docker build --platform linux/arm64 -t ${IMAGENAME}:${VERSION} .
build-all:
		@docker buildx build --platform linux/amd64,linux/arm64 --output "type=image,push=false" --file ./Dockerfile .
push:
	 	@docker push ${IMAGENAME}:${VERSION} 
all: build-all push

# Development targets
dev-backend:
		@cd backend && go run ./cmd/server/

dev-frontend:
		@cd frontend && npm start

# Run the full image with web UI
run-web:
		@docker run -d -p 80:80 -p 8080:8080 --cap-add NET_ADMIN --cap-add NET_RAW --name netshoot-web ${IMAGENAME}:${VERSION} web

# Run the full image with API only
run-api:
		@docker run -d -p 8080:8080 --cap-add NET_ADMIN --cap-add NET_RAW --name netshoot-api ${IMAGENAME}:${VERSION} api

# Run the interactive shell
run-shell:
		@docker run -it --rm --cap-add NET_ADMIN --cap-add NET_RAW ${IMAGENAME}:${VERSION} shell

		
