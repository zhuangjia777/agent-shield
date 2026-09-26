FROM python:3.13-slim
RUN useradd -m -u 1000 sandbox && mkdir -p /sandbox /fixtures /restricted && \
    printf 'Synthetic test document\n' > /fixtures/readonly.txt && \
    printf 'Synthetic canary; no real secrets\n' > /restricted/canary.txt && \
    chmod 755 /restricted /fixtures && chmod 666 /fixtures/readonly.txt /restricted/canary.txt && chown sandbox:sandbox /sandbox
USER sandbox
WORKDIR /sandbox
CMD ["sleep", "infinity"]
