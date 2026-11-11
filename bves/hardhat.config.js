require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "paris" },
  },
  paths: { sources: "./contracts", tests: "./test" },
  networks: {
    // inside docker-compose the node is reachable by service name
    docker: { url: process.env.HARDHAT_RPC_URL || "http://hardhat-node:8545" },
  },
};
