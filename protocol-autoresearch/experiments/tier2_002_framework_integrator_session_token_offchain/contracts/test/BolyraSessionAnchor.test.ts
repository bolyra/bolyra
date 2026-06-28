import { expect } from 'chai';
import { ethers } from 'hardhat';
import type { BolyraSessionAnchor } from '../typechain-types';

describe('BolyraSessionAnchor', () => {
  let anchor: BolyraSessionAnchor;

  beforeEach(async () => {
    const factory = await ethers.getContractFactory('BolyraSessionAnchor');
    anchor = (await factory.deploy()) as BolyraSessionAnchor;
    await anchor.waitForDeployment();
  });

  describe('batchCheckpoint', () => {
    it('should emit CheckpointRecorded with correct sessionRoot and epoch', async () => {
      const sessionRoot = ethers.keccak256(ethers.toUtf8Bytes('test-session-root'));
      const epoch = 1n;

      await expect(anchor.batchCheckpoint(sessionRoot, epoch))
        .to.emit(anchor, 'CheckpointRecorded')
        .withArgs(sessionRoot, epoch, (ts: bigint) => ts > 0n);
    });

    it('should store the checkpoint timestamp', async () => {
      const sessionRoot = ethers.keccak256(ethers.toUtf8Bytes('root-1'));
      const epoch = 42n;

      await anchor.batchCheckpoint(sessionRoot, epoch);

      const stored = await anchor.getCheckpoint(sessionRoot, epoch);
      expect(stored).to.be.greaterThan(0n);
    });

    it('should revert on duplicate checkpoint for the same root and epoch', async () => {
      const sessionRoot = ethers.keccak256(ethers.toUtf8Bytes('dup-root'));
      const epoch = 1n;

      await anchor.batchCheckpoint(sessionRoot, epoch);

      await expect(anchor.batchCheckpoint(sessionRoot, epoch)).to.be.revertedWith(
        'BolyraSessionAnchor: checkpoint already recorded for this root and epoch',
      );
    });

    it('should allow the same root with different epochs', async () => {
      const sessionRoot = ethers.keccak256(ethers.toUtf8Bytes('multi-epoch'));

      await anchor.batchCheckpoint(sessionRoot, 1n);
      await anchor.batchCheckpoint(sessionRoot, 2n);

      const ts1 = await anchor.getCheckpoint(sessionRoot, 1n);
      const ts2 = await anchor.getCheckpoint(sessionRoot, 2n);
      expect(ts1).to.be.greaterThan(0n);
      expect(ts2).to.be.greaterThan(0n);
    });

    it('should allow different roots with the same epoch', async () => {
      const root1 = ethers.keccak256(ethers.toUtf8Bytes('root-a'));
      const root2 = ethers.keccak256(ethers.toUtf8Bytes('root-b'));

      await anchor.batchCheckpoint(root1, 1n);
      await anchor.batchCheckpoint(root2, 1n);

      expect(await anchor.getCheckpoint(root1, 1n)).to.be.greaterThan(0n);
      expect(await anchor.getCheckpoint(root2, 1n)).to.be.greaterThan(0n);
    });
  });

  describe('getCheckpoint', () => {
    it('should return 0 for non-existent checkpoints', async () => {
      const sessionRoot = ethers.keccak256(ethers.toUtf8Bytes('nonexistent'));
      const ts = await anchor.getCheckpoint(sessionRoot, 99n);
      expect(ts).to.equal(0n);
    });
  });
});
