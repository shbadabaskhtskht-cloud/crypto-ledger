# Crypto shares ledger server — deploy-ready.
# Single file (server.js) + SQLite. No build step, no dependencies.
FROM node:24-alpine
WORKDIR /app
COPY server.js ./server.js
EXPOSE 8787
ENV PORT=8787
CMD ["node", "server.js"]
