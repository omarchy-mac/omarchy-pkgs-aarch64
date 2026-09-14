ARG BASE_IMAGE=archlinux:base-devel
FROM ${BASE_IMAGE}
COPY scripts/container-bootstrap.sh /publisher-bootstrap.sh
RUN bash /publisher-bootstrap.sh >/dev/null && rm /publisher-bootstrap.sh
