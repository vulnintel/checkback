# Clean-room install of the packed checkback tarball (see run.sh). git is the only extra tool:
# checkback reads git history for committed .env / key files.
ARG NODE_IMAGE=node:22-slim
FROM ${NODE_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
COPY .pack/checkback.tgz /tmp/checkback.tgz
RUN npm install -g /tmp/checkback.tgz && rm /tmp/checkback.tgz
COPY e2e.mjs /e2e/e2e.mjs
USER node
WORKDIR /home/node
ENTRYPOINT ["node", "/e2e/e2e.mjs"]
CMD ["online"]
