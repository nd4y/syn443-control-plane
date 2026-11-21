FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS trust
FROM scratch
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0555 telemetry-ingest /telemetry-ingest
ARG VCS_REF
LABEL org.opencontainers.image.revision=$VCS_REF
ENV SYN443_TELEMETRY_CONFIG=/run/syn443/telemetry/config.json
USER 65532:65532
ENTRYPOINT ["/telemetry-ingest"]
HEALTHCHECK --interval=30s --timeout=6s --retries=3 CMD ["/telemetry-ingest", "--check-ready"]
