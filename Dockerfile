FROM alpine:3.17@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501 as builder

RUN apk add git=2.38.5-r0 && \
	apk add make=4.3-r1 && \
	apk add pkgconf=1.9.4-r0 && \
	apk add libelf=0.187-r2 && \
	apk add libelf-static=0.187-r2 && \
	apk add elfutils-dev=0.187-r2 && \
	apk add zlib=1.2.13-r0 && \
	apk add zlib-static=1.2.13-r0 && \
	apk add linux-headers=5.19.5-r0 && \
	apk add musl-dev=1.2.3-r5 && \
	apk add gcc=12.2.1_git20220924-r4 && \
	apk add go=1.19.9-r0 && \
	apk add clang=15.0.7-r0 && \
	apk add llvm=15.0.7-r0 && \
	rm -rf /var/cache/apk/*

COPY . /template

WORKDIR /template

RUN make clean && make

FROM alpine:3.17@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501

WORKDIR /template

COPY --from=builder /template/xdp /template/xdp
COPY --from=builder /template/xdp.bpf.o /template/xdp.bpf.o

ENTRYPOINT ["/template/xdp"]
