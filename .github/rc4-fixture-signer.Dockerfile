# Provenance-only recipe; all tools must already exist in the reviewed base.
# Labels are claims bound to an independently reviewed final image digest,
# not proof of reproducibility or authenticated build provenance.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG DOCKERFILE_BLOB_SHA
ARG BASE_IMAGE_DIGEST
LABEL org.omarchy.rc4.dockerfile-blob-sha="${DOCKERFILE_BLOB_SHA}" \
      org.omarchy.rc4.base-image-digest="${BASE_IMAGE_DIGEST}"
