FROM ubuntu:jammy as base

RUN apt-get update -q \
  && apt-get install -q -y build-essential clang \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*
  
COPY ./harness/ /opt/
RUN cd /opt/ && make clean && make



FROM snapchange

COPY --from=base / "$SNAPSHOT_INPUT"

ENV SNAPSHOT_ENTRYPOINT=/opt/example
ENV SNAPSHOT_ENTRYPOINT_CWD="/tmp/"
ENV SNAPSHOT_IMGTYPE=disk
ENV LIBFUZZER=1
