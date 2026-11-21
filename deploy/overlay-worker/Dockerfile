FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS trust
FROM scratch
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0555 overlay-worker /overlay-worker
ARG VCS_REF
LABEL org.opencontainers.image.revision=$VCS_REF
ENV SYN443_OVERLAY_BROKER_CONFIG=/run/secrets/overlay-worker.json
USER 65532:65532
ENTRYPOINT ["/overlay-worker"]
HEALTHCHECK --interval=30s --timeout=8s --retries=3 CMD ["/overlay-worker", "--check-ready"]
