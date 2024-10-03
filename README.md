# Suffragium

Suffragium is a voting system that leverages zero-knowledge (zk) proofs and ‍Fully Homomorphic Encryption (FHE) to preserve all essential properties of a secure voting system. It utilizes [sp1-dkim](https://github.com/allemanfredi/sp1-dkim) to generate a zk proof, verifying that a registered user is eligible to vote after having completed the KYC. Additionally, it employs fully homomorphic encryption (thanks to [zama](https://www.zama.ai/)) to prevent bribery and blackmail by ensuring that votes remain private and confidential. This voting system aims to simulate and enhance the current voting process by ensuring that users are properly authenticated while maintaining privacy and security. The system is currently still under development, with ongoing improvements to enhance its security and functionality. 

## Usage

### Pre Requisites

Install [docker](https://docs.docker.com/engine/install/)

Install [pnpm](https://pnpm.io/installation)

Before being able to run any command, you need to create a `.env` file and set a BIP-39 compatible mnemonic as an
environment variable. You can follow the example in `.env.example` and start with the following command:

```sh
cp .env.example .env
```

If you don't already have a mnemonic, you can use this [website](https://iancoleman.io/bip39/) to generate one.

Then, proceed with installing dependencies - please **_make sure to use Node v20_** or more recent or this will fail:

```sh
pnpm install
```

### Start fhEVM

During installation (see previous section) we recommend you for easier setup to not change the default `.env` : simply
copy the original `.env.example` file to a new `.env` file in the root of the repo.

Then, start a local fhEVM docker compose that inlcudes everything needed to deploy FHE encrypted smart contracts using:

```sh
# In one terminal, keep it opened
# The node logs are printed
pnpm fhevm:start
```

Previous command will take 2 to 3 minutes to do the whole initial setup - wait until the blockchain logs appear to make
sure setup is complete (we are working on making initial deployment faster).

You can then run the tests simply in a new terminal via :

```
pnpm test
```

Once your done with your tests, to stop the node:

```sh
pnpm fhevm:stop
```

### Compile

Compile the smart contracts with Hardhat:

```sh
pnpm compile
```

### TypeChain

Compile the smart contracts and generate TypeChain bindings:

```sh
pnpm typechain
```

### List accounts

From the mnemonic in .env file, list all the derived Ethereum adresses:

```sh
pnpm task:accounts
```

### Get some native coins

In order to interact with the blockchain, one need some coins. This command will give coins to the first 5 addresses
derived from the mnemonic in .env file.

```sh
pnpm fhevm:faucet
```

<br />
<details>
  <summary>To get the first derived address from mnemonic</summary>
<br />

```sh
pnpm task:getEthereumAddress
```

</details>
<br />

### Test

Run the tests with Hardhat:

```sh
pnpm test
```

### Lint Solidity

Lint the Solidity code:

```sh
pnpm lint:sol
```

### Lint TypeScript

Lint the TypeScript code:

```sh
pnpm lint:ts
```

### Report Gas

See the gas usage per unit test and average gas per method call:

```sh
REPORT_GAS=true pnpm test
```

### Clean

Delete the smart contract artifacts, the coverage reports and the Hardhat cache:

```sh
pnpm clean
```

### Mocked mode

The mocked mode allows faster testing and the ability to analyze coverage of the tests. In this mocked version,
encrypted types are not really encrypted, and the tests are run on the original version of the EVM, on a local hardhat
network instance. To run the tests in mocked mode, you can use directly the following command:

```bash
pnpm test:mock
```

To analyze the coverage of the tests (in mocked mode necessarily, as this cannot be done on the real fhEVM node), you
can use this command :

```bash
pnpm coverage:mock
```

Then open the file `coverage/index.html`. You can see there which line or branch for each contract which has been
covered or missed by your test suite. This allows increased security by pointing out missing branches not covered yet by
the current tests.

> [!Note]
> Due to intrinsic limitations of the original EVM, the mocked version differ in few corner cases from the real fhEVM, the main difference is the difference in gas prices for the FHE operations. This means that before deploying to production, developers still need to run the tests with the original fhEVM node, as a final check in non-mocked mode, with `pnpm test`.

### Syntax Highlighting

If you use VSCode, you can get Solidity syntax highlighting with the
[hardhat-solidity](https://marketplace.visualstudio.com/items?itemName=NomicFoundation.hardhat-solidity) extension.

## License

This project is licensed under MIT.
