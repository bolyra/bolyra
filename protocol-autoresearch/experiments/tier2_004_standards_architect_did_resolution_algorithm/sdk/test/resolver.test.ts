import { expect } from "chai";
import { ethers } from "hardhat";
import { resolve, parseDid, getBolyraResolver } from "../src/resolver";
import {
  buildAgentVerificationMethod,
  buildHumanVerificationMethod,
  toBase64Url,
  fromBase64Url,
  BOLYRA_DID_CONTEXT,
  errorResult,
} from "../src/didDocument";
import type { BolyraResolverOptions } from "../src/resolver";

describe("did:bolyra Resolver", function () {
  let registry: any;
  let registryAddress: string;
  let owner: any;
  let resolverOptions: BolyraResolverOptions;

  // Test commitments (64 hex chars)
  const agentCommitment =
    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  const agentCommitmentHex =
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  const humanCommitment =
    "0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
  const humanCommitmentHex =
    "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
  const revokedCommitment =
    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
  const revokedCommitmentHex =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
  const unknownCommitmentHex =
    "0000000000000000000000000000000000000000000000000000000000000001";

  // 64-byte agent public key (x || y)
  const agentPubKey = ethers.hexlify(ethers.randomBytes(64));
  const merkleRoot = ethers.hexlify(ethers.randomBytes(32));

  before(async function () {
    [owner] = await ethers.getSigners();

    const RegistryFactory = await ethers.getContractFactory(
      "IdentityRegistry"
    );
    registry = await RegistryFactory.deploy();
    await registry.waitForDeployment();
    registryAddress = await registry.getAddress();

    // Register an agent
    await registry.register(agentCommitment, 1, agentPubKey, merkleRoot);

    // Register a human
    await registry.register(humanCommitment, 0, "0x", merkleRoot);

    // Register and revoke
    await registry.register(revokedCommitment, 1, agentPubKey, merkleRoot);
    await registry.revoke(revokedCommitment);

    resolverOptions = {
      provider: owner.provider!,
      registryAddress,
      chainId: 31337,
      chainName: "Hardhat",
    };
  });

  // --- parseDid ---

  describe("parseDid", function () {
    it("should parse a valid did:bolyra DID", function () {
      const result = parseDid(`did:bolyra:${agentCommitmentHex}`);
      expect(result).to.equal(agentCommitmentHex);
    });

    it("should reject uppercase hex", function () {
      const result = parseDid("did:bolyra:AABB" + "0".repeat(60));
      expect(result).to.be.null;
    });

    it("should reject short commitment", function () {
      const result = parseDid("did:bolyra:abcd");
      expect(result).to.be.null;
    });

    it("should reject 0x prefix in commitment", function () {
      const result = parseDid("did:bolyra:0x" + "a".repeat(64));
      expect(result).to.be.null;
    });

    it("should reject other DID methods", function () {
      const result = parseDid("did:key:z6Mkf5rGM" + "0".repeat(50));
      expect(result).to.be.null;
    });
  });

  // --- resolve: agent ---

  describe("resolve agent DID", function () {
    it("should return a valid DID Document with JsonWebKey2020", async function () {
      const did = `did:bolyra:${agentCommitmentHex}`;
      const result = await resolve(did, resolverOptions);

      expect(result.didResolutionMetadata.error).to.be.undefined;
      expect(result.didResolutionMetadata.contentType).to.equal(
        "application/did+ld+json"
      );
      expect(result.didDocument).to.not.be.null;

      const doc = result.didDocument!;
      expect(doc["@context"]).to.deep.equal([...BOLYRA_DID_CONTEXT]);
      expect(doc.id).to.equal(did);
      expect(doc.controller).to.equal(did);

      // Verification method
      expect(doc.verificationMethod).to.have.lengthOf(1);
      const vm = doc.verificationMethod[0];
      expect(vm.type).to.equal("JsonWebKey2020");
      expect(vm.id).to.equal(`${did}#agent-key-1`);
      expect(vm.controller).to.equal(did);

      // JWK fields
      expect((vm as any).publicKeyJwk.kty).to.equal("OKP");
      expect((vm as any).publicKeyJwk.crv).to.equal("Baby-Jubjub");
      expect((vm as any).publicKeyJwk.x).to.be.a("string");
      expect((vm as any).publicKeyJwk.y).to.be.a("string");

      // Authentication and assertionMethod (agent has both)
      expect(doc.authentication).to.deep.equal([`${did}#agent-key-1`]);
      expect(doc.assertionMethod).to.deep.equal([`${did}#agent-key-1`]);

      // Service
      expect(doc.service).to.have.lengthOf(1);
      expect(doc.service[0].type).to.equal("BolyraRegistryService");
      expect(doc.service[0].serviceEndpoint.registryAddress).to.equal(
        registryAddress
      );
      expect(doc.service[0].serviceEndpoint.chainId).to.equal(31337);
    });

    it("should include correct metadata", async function () {
      const did = `did:bolyra:${agentCommitmentHex}`;
      const result = await resolve(did, resolverOptions);

      expect(result.didDocumentMetadata.created).to.be.a("string");
      expect(result.didDocumentMetadata.deactivated).to.equal(false);
    });
  });

  // --- resolve: human ---

  describe("resolve human DID", function () {
    it("should return a valid DID Document with BolyraZkpAuthentication2024", async function () {
      const did = `did:bolyra:${humanCommitmentHex}`;
      const result = await resolve(did, resolverOptions);

      expect(result.didResolutionMetadata.error).to.be.undefined;
      expect(result.didDocument).to.not.be.null;

      const doc = result.didDocument!;
      expect(doc.id).to.equal(did);

      // Verification method
      expect(doc.verificationMethod).to.have.lengthOf(1);
      const vm = doc.verificationMethod[0];
      expect(vm.type).to.equal("BolyraZkpAuthentication2024");
      expect(vm.id).to.equal(`${did}#human-auth-1`);
      expect((vm as any).nullifierCommitment).to.equal(humanCommitmentHex);
      expect((vm as any).merkleTreeDepth).to.equal(20);

      // Human: authentication only, no assertionMethod
      expect(doc.authentication).to.deep.equal([`${did}#human-auth-1`]);
      expect(doc.assertionMethod).to.deep.equal([]);
    });
  });

  // --- resolve: not found ---

  describe("resolve unknown DID", function () {
    it("should return notFound error", async function () {
      const did = `did:bolyra:${unknownCommitmentHex}`;
      const result = await resolve(did, resolverOptions);

      expect(result.didResolutionMetadata.error).to.equal("notFound");
      expect(result.didDocument).to.be.null;
    });
  });

  // --- resolve: deactivated ---

  describe("resolve deactivated DID", function () {
    it("should return deactivated error with metadata flag", async function () {
      const did = `did:bolyra:${revokedCommitmentHex}`;
      const result = await resolve(did, resolverOptions);

      expect(result.didResolutionMetadata.error).to.equal("deactivated");
      expect(result.didDocument).to.be.null;
      expect(result.didDocumentMetadata.deactivated).to.equal(true);
    });
  });

  // --- resolve: invalid DIDs ---

  describe("resolve invalid DIDs", function () {
    it("should return invalidDid for malformed DID", async function () {
      const result = await resolve("did:bolyra:not-valid-hex", resolverOptions);
      expect(result.didResolutionMetadata.error).to.equal("invalidDid");
    });

    it("should return invalidDid for too-short commitment", async function () {
      const result = await resolve("did:bolyra:abcdef", resolverOptions);
      expect(result.didResolutionMetadata.error).to.equal("invalidDid");
    });

    it("should return methodNotSupported for other methods", async function () {
      const result = await resolve("did:key:z6MkhaXgBZD" + "0".repeat(52), resolverOptions);
      expect(result.didResolutionMetadata.error).to.equal(
        "methodNotSupported"
      );
    });

    it("should return invalidDid for totally broken string", async function () {
      const result = await resolve("not-a-did", resolverOptions);
      expect(result.didResolutionMetadata.error).to.equal("invalidDid");
    });
  });

  // --- DID Document builder unit tests ---

  describe("DID Document builders", function () {
    it("toBase64Url and fromBase64Url roundtrip", function () {
      const original = new Uint8Array(32);
      for (let i = 0; i < 32; i++) original[i] = i;
      const encoded = toBase64Url(original);
      const decoded = fromBase64Url(encoded);
      expect(Buffer.from(original)).to.deep.equal(decoded);
    });

    it("buildAgentVerificationMethod returns correct shape", function () {
      const x = new Uint8Array(32).fill(1);
      const y = new Uint8Array(32).fill(2);
      const vm = buildAgentVerificationMethod(
        "did:bolyra:" + "aa".repeat(32),
        x,
        y
      );
      expect(vm.type).to.equal("JsonWebKey2020");
      expect(vm.publicKeyJwk.kty).to.equal("OKP");
      expect(vm.publicKeyJwk.crv).to.equal("Baby-Jubjub");
    });

    it("buildHumanVerificationMethod returns correct shape", function () {
      const vm = buildHumanVerificationMethod(
        "did:bolyra:" + "bb".repeat(32),
        "bb".repeat(32)
      );
      expect(vm.type).to.equal("BolyraZkpAuthentication2024");
      expect(vm.proofPurpose).to.equal("authentication");
      expect(vm.merkleTreeDepth).to.equal(20);
    });

    it("errorResult returns correct structure", function () {
      const result = errorResult("notFound");
      expect(result.didDocument).to.be.null;
      expect(result.didResolutionMetadata.error).to.equal("notFound");
      expect(result.didDocumentMetadata).to.deep.equal({});
    });

    it("errorResult deactivated includes metadata flag", function () {
      const result = errorResult("deactivated");
      expect(result.didDocumentMetadata.deactivated).to.equal(true);
    });
  });

  // --- getBolyraResolver (did-resolver integration) ---

  describe("getBolyraResolver", function () {
    it("should return an object with a bolyra key", function () {
      const methods = getBolyraResolver(resolverOptions);
      expect(methods).to.have.property("bolyra");
      expect(methods.bolyra).to.be.a("function");
    });

    it("should resolve via the driver function", async function () {
      const methods = getBolyraResolver(resolverOptions);
      const did = `did:bolyra:${agentCommitmentHex}`;
      const result = await methods.bolyra(did, {}, {}, {});
      expect(result.didDocument).to.not.be.null;
      expect(result.didDocument!.id).to.equal(did);
    });
  });
});
