# syntax=docker/dockerfile:1
# Local Ethereum node + one-shot deployer (same image, different command).
FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN npm config set fetch-retries 5 && npm config set fetch-timeout 300000
RUN --mount=type=cache,target=/root/.npm npm install --no-audit --no-fund
COPY hardhat.config.js ./
COPY contracts ./contracts
COPY scripts/deploy.js ./scripts/deploy.js
# The solc download is cached by Hardhat under ~/.cache; keep it between attempts too.
RUN --mount=type=cache,target=/root/.cache/hardhat-nodejs npx hardhat compile
EXPOSE 8545
CMD ["npx", "hardhat", "node", "--hostname", "0.0.0.0"]
