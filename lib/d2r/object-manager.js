'use strict';

const { EventEmitter } = require('events');
const { readMemoryInto, tryWithGameLock, highResolutionTime, invalidateCache } = require('memory');
const { UnitModel } = require('d2r/models');
const { UnitTypes } = require('d2r/types');
const { Player, LocalPlayer } = require('d2r/player');
const { Monster } = require('d2r/monster');
const { Item } = require('d2r/item');
const { GameObject } = require('d2r/game-object');
const { Missile } = require('d2r/missile');
const { RoomTile } = require('d2r/room-tile');

const binding = internalBinding('d2r');

// TODO: move to nyx:utils
function getTimeNs() {
  return Number(highResolutionTime());
}

// TODO: move to nyx:utils
function formatTime(ns) {
  if (ns < 1000) return `${ns.toFixed(1)}ns`;
  if (ns < 1000000) return `${(ns / 1000).toFixed(2)}us`;
  if (ns < 1000000000) return `${(ns / 1000000).toFixed(2)}ms`;
  return `${(ns / 1000000000).toFixed(2)}s `;
}

const BUCKET_COUNT = 128;
const TYPE_COUNT = 6;
const POINTER_COUNT = TYPE_COUNT * BUCKET_COUNT;
const MAX_CHAIN_NODES = 8192;
const UNIT_HEADER_SIZE = 0x160;
const MAX_INCREMENTAL_NODES_PER_TICK = 4;
const INCREMENTAL_WORK_BUDGET_NS = 4_000_000;
const INCREMENTAL_TYPE_ORDER = [
  UnitTypes.Player,
  UnitTypes.Monster,
  UnitTypes.Missile,
  UnitTypes.Object,
  UnitTypes.Item,
  UnitTypes.Tile,
];
const pointerBuffer = new Uint8Array(POINTER_COUNT * 8);
const pointerView = new DataView(
  pointerBuffer.buffer,
  pointerBuffer.byteOffset,
  pointerBuffer.byteLength,
);
const bucketPointerBuffer = new Uint8Array(8);
const bucketPointerView = new DataView(
  bucketPointerBuffer.buffer,
  bucketPointerBuffer.byteOffset,
  bucketPointerBuffer.byteLength,
);

class ObjectManager extends EventEmitter {
  constructor(options = {}) {
    super();
    this._units = new Array(TYPE_COUNT);
    this._cursor = UnitModel.createCursor(1);
    this._incrementalHeaderBuffer = new Uint8Array(UNIT_HEADER_SIZE);
    this._incrementalHeaderView = new DataView(
      this._incrementalHeaderBuffer.buffer,
      this._incrementalHeaderBuffer.byteOffset,
      this._incrementalHeaderBuffer.byteLength,
    );
    this._localPlayerId = -1;
    this._lastReadOnlyScanError = '';
    this.me = null;
    this._lastTickTime = '';
    this._lastGameLockTime = '';
    this._lastTickTimeNs = 0;
    this._lastGameLockTimeNs = 0;
    this._lastChainWarnMs = 0;
    this._chainIssueWindowStartMs = 0;
    this._chainIssueCount = 0;
    this._riskCircuitTripped = false;
    this._logChainIssues = !!options.logChainIssues;
    this._logRiskCircuit = !!options.logRiskCircuit;
    this._logInfo = typeof options.logInfo === 'function' ? options.logInfo : (...args) => console.log(...args);
    this._logError = typeof options.logError === 'function' ? options.logError : (...args) => console.error(...args);
    this._incrementalBucket = 0;
    this._incrementalTypeOrderIndex = 0;
    this._incrementalType = INCREMENTAL_TYPE_ORDER[0];
    this._incrementalCurrentPtr = 0n;
    this._incrementalChainVisited = new Set();
    this._incrementalChainNodes = 0;
    this._incrementalCycleCount = 0;
    this._incrementalSeen = new Array(TYPE_COUNT);
    this._incrementalTableAddress = 0n;
    this._incrementalPointerSnapshotReady = false;
    this.reset();
  }

  reset() {
    for (let i = 0; i < TYPE_COUNT; i++) {
      this._units[i] = new Map();
      this._incrementalSeen[i] = new Set();
    }
    this._incrementalBucket = 0;
    this._incrementalTypeOrderIndex = 0;
    this._incrementalType = INCREMENTAL_TYPE_ORDER[0];
    this._incrementalCurrentPtr = 0n;
    this._incrementalChainVisited.clear();
    this._incrementalChainNodes = 0;
    this._incrementalCycleCount = 0;
    this._incrementalTableAddress = 0n;
    this._incrementalPointerSnapshotReady = false;
    this.me = null;
    this._lastReadOnlyScanError = '';
  }

  getUnits(type) {
    return this._units[type];
  }

  hasLocalPlayerCandidate() {
    const playerId = tryWithGameLock(() => (
      binding.getPlayerIdByIndex(binding.getLocalPlayerIndex())
    ));
    return Number.isInteger(playerId) && playerId >= 0;
  }

  tickIncrementalClient() {
    const tickStart = getTimeNs();
    invalidateCache();

    try {
      this._localPlayerId = binding.getPlayerIdByIndex(binding.getLocalPlayerIndex());
      if (!Number.isInteger(this._localPlayerId) || this._localPlayerId < 0) return false;
      const tableAddress = binding.getClientSideUnitHashTableAddress();

      for (let workItem = 0; workItem < MAX_INCREMENTAL_NODES_PER_TICK; workItem++) {
        this._ensureIncrementalPointerSnapshot(tableAddress);
        let scannedNode = false;

        // Empty buckets are cheap. Bound both decoded units and wall-clock work.
        for (let probe = 0; probe < POINTER_COUNT; probe++) {
          if (this._incrementalCurrentPtr === 0n) {
            this._incrementalCurrentPtr = this._readIncrementalBucketPointer(
              this._incrementalType,
              this._incrementalBucket,
            );
            this._incrementalChainVisited.clear();
            this._incrementalChainNodes = 0;
            if (this._incrementalCurrentPtr === 0n) {
              this._advanceIncrementalPosition();
              continue;
            }
          }

          const nextPtr = this._scanIncrementalNode(
            this._incrementalCurrentPtr,
            this._incrementalType,
            this._incrementalBucket,
            this._incrementalSeen[this._incrementalType],
          );
          if (nextPtr === 0n) {
            this._advanceIncrementalPosition();
          } else {
            this._incrementalCurrentPtr = nextPtr;
          }
          scannedNode = true;
          break;
        }

        if (!scannedNode || getTimeNs() - tickStart >= INCREMENTAL_WORK_BUDGET_NS) break;
      }
    } catch (e) {
      this._logInfo(`[ObjectManager] incremental read skipped: ${e?.message ?? e}`);
      return false;
    }

    if (this.me && !this.me.isValid) this.me = null;
    if (this.me === null && this._units[UnitTypes.Player].has(this._localPlayerId)) {
      this.me = this._units[UnitTypes.Player].get(this._localPlayerId);
    }

    this._lastTickTimeNs = getTimeNs() - tickStart;
    this._lastGameLockTimeNs = 0;
    this._lastTickTime = formatTime(this._lastTickTimeNs);
    this._lastGameLockTime = '0.0ns';
    return true;
  }

  tickFullClientReadOnly() {
    const tickStart = getTimeNs();
    invalidateCache();

    const seen = new Array(TYPE_COUNT);
    for (let type = 0; type < TYPE_COUNT; type++) seen[type] = new Set();

    try {
      const localIndex = binding.getLocalPlayerIndex();
      this._localPlayerId = Number.isInteger(localIndex) && localIndex >= 0
        ? binding.getPlayerIdByIndex(localIndex)
        : -1;
    } catch (_) {
      this._localPlayerId = -1;
    }

    try {
      const tableAddress = binding.getClientSideUnitHashTableAddress();
      readMemoryInto(tableAddress, pointerBuffer);

      for (const type of INCREMENTAL_TYPE_ORDER) {
        for (let bucket = 0; bucket < BUCKET_COUNT; bucket++) {
          const pointerIndex = type * BUCKET_COUNT + bucket;
          let currentPtr = pointerView.getBigUint64(pointerIndex * 8, true);
          this._incrementalChainVisited.clear();
          this._incrementalChainNodes = 0;

          while (currentPtr !== 0n) {
            const nextPtr = this._scanIncrementalNode(
              currentPtr,
              type,
              bucket,
              seen[type],
            );
            if (nextPtr === 0n) break;
            currentPtr = nextPtr;
          }
        }
      }
    } catch (e) {
      this._lastReadOnlyScanError = String(e?.message ?? e);
      this._logInfo(`[ObjectManager] full client read skipped: ${e?.message ?? e}`);
      return false;
    }
    this._lastReadOnlyScanError = '';

    for (let type = 0; type < TYPE_COUNT; type++) {
      const existing = this._units[type];
      for (const [id, unit] of existing) {
        if (!seen[type].has(id)) {
          this.emit('unitRemoved', unit, type);
          unit._invalidate();
          existing.delete(id);
        }
      }
    }

    if (this.me && !this.me.isValid) this.me = null;
    const players = this._units[UnitTypes.Player];
    if (this.me === null && Number.isInteger(this._localPlayerId) && this._localPlayerId >= 0
        && players.has(this._localPlayerId)) {
      this.me = players.get(this._localPlayerId);
    }
    if (this.me === null && players.size === 1) {
      this.me = players.values().next().value;
    }

    this._incrementalCycleCount++;
    this._lastTickTimeNs = getTimeNs() - tickStart;
    this._lastGameLockTimeNs = 0;
    this._lastTickTime = formatTime(this._lastTickTimeNs);
    this._lastGameLockTime = '0.0ns';
    return true;
  }

  get incrementalCycleCount() {
    return this._incrementalCycleCount;
  }

  get localPlayerId() {
    return this._localPlayerId;
  }

  get lastReadOnlyScanError() {
    return this._lastReadOnlyScanError;
  }

  tick() {
    const tick_start = getTimeNs();

    invalidateCache();

    const seen = new Array(TYPE_COUNT);
    for (let i = 0; i < TYPE_COUNT; i++) seen[i] = new Set();

    const game_lock_elapsed = tryWithGameLock(() => {
      const game_lock_start = getTimeNs();
      this._localPlayerId = binding.getPlayerIdByIndex(binding.getLocalPlayerIndex());
      this._scanTable(binding.getClientSideUnitHashTableAddress(), seen);
      this._scanTable(binding.getServerSideUnitHashTableAddress(), seen);
      return getTimeNs() - game_lock_start;
    });
    // failed to grab game lock due to timeout (game frozen)
    if (game_lock_elapsed === undefined) {
      return false;
    }

    for (let type = 0; type < TYPE_COUNT; type++) {
      const existing = this._units[type];
      for (const [id, unit] of existing) {
        if (!seen[type].has(id)) {
          this.emit('unitRemoved', unit, type);
          unit._invalidate();
          existing.delete(id);
        }
      }
    }

    if (this.me && !this.me.isValid) {
      this.me = null;
    }
    if (this.me === null && this._units[0].has(this._localPlayerId)) {
      this.me = this._units[0].get(this._localPlayerId);
    }

    this._lastTickTimeNs = getTimeNs() - tick_start;
    this._lastGameLockTimeNs = game_lock_elapsed;
    this._lastTickTime = formatTime(this._lastTickTimeNs);
    this._lastGameLockTime = formatTime(this._lastGameLockTimeNs);
    return true;
  }

  get tickTime() {
    return this._lastTickTime;
  }

  get tickTimeNs() {
    return this._lastTickTimeNs;
  }

  get gameLockTime() {
    return this._lastGameLockTime;
  }

  get gameLockTimeNs() {
    return this._lastGameLockTimeNs;
  }

  isRiskCircuitTripped() {
    return this._riskCircuitTripped;
  }

  _scanTable(tableAddress, seen) {
    readMemoryInto(tableAddress, pointerBuffer);

    for (let i = 0; i < POINTER_COUNT; i++) {
      const ptr = pointerView.getBigUint64(i * 8, true);
      if (ptr === 0n) continue;

      const type = (i / BUCKET_COUNT) | 0;
      this._scanChain(ptr, type, i, seen[type]);
    }
  }

  _scanTableBucket(tableAddress, type, bucket, seen) {
    const ptr = this._readTableBucketPointer(tableAddress, type, bucket);
    if (ptr !== 0n) this._scanChain(ptr, type, bucket, seen);
  }

  _readTableBucketPointer(tableAddress, type, bucket) {
    const pointerOffset = BigInt((type * BUCKET_COUNT + bucket) * 8);
    readMemoryInto(tableAddress + pointerOffset, bucketPointerBuffer);
    return bucketPointerView.getBigUint64(0, true);
  }

  _ensureIncrementalPointerSnapshot(tableAddress) {
    if (this._incrementalPointerSnapshotReady &&
        this._incrementalTableAddress === tableAddress) return;

    readMemoryInto(tableAddress, pointerBuffer);
    this._incrementalTableAddress = tableAddress;
    this._incrementalPointerSnapshotReady = true;
  }

  _readIncrementalBucketPointer(type, bucket) {
    const pointerIndex = type * BUCKET_COUNT + bucket;
    return pointerView.getBigUint64(pointerIndex * 8, true);
  }

  _advanceIncrementalPosition() {
    this._incrementalCurrentPtr = 0n;
    this._incrementalChainVisited.clear();
    this._incrementalChainNodes = 0;
    this._incrementalBucket++;
    if (this._incrementalBucket < BUCKET_COUNT) return;

    this._incrementalBucket = 0;
    this._incrementalTypeOrderIndex++;
    if (this._incrementalTypeOrderIndex < INCREMENTAL_TYPE_ORDER.length) {
      this._incrementalType = INCREMENTAL_TYPE_ORDER[this._incrementalTypeOrderIndex];
      return;
    }

    this._incrementalTypeOrderIndex = 0;
    this._incrementalType = INCREMENTAL_TYPE_ORDER[0];
    this._incrementalPointerSnapshotReady = false;
    for (let type = 0; type < TYPE_COUNT; type++) {
      const existing = this._units[type];
      const seen = this._incrementalSeen[type];
      for (const [id, unit] of existing) {
        if (!seen.has(id)) {
          this.emit('unitRemoved', unit, type);
          unit._invalidate();
          existing.delete(id);
        }
      }
      seen.clear();
    }
    this._incrementalCycleCount++;
  }

  _scanIncrementalNode(currentPtr, type, bucket, seen) {
    if (this._incrementalChainVisited.has(currentPtr)) {
      this._warnChainIssue(type, bucket, currentPtr, 'cycle detected');
      return 0n;
    }
    this._incrementalChainVisited.add(currentPtr);
    if (++this._incrementalChainNodes > MAX_CHAIN_NODES) {
      this._warnChainIssue(type, bucket, currentPtr, `traversal cap ${MAX_CHAIN_NODES} reached`);
      return 0n;
    }

    try {
      readMemoryInto(currentPtr, this._incrementalHeaderBuffer);
    } catch (e) {
      this._warnChainIssue(type, bucket, currentPtr, `header read failed: ${e?.message ?? e}`);
      return 0n;
    }

    const view = this._incrementalHeaderView;
    const actualType = view.getUint32(0x00, true);
    const id = view.getUint32(0x08, true);
    if (actualType !== type || id === 0xFFFFFFFF) {
      this._warnChainIssue(
        type,
        bucket,
        currentPtr,
        `invalid header type=${actualType} id=0x${id.toString(16)}`,
      );
      return 0n;
    }

    let unit = this._units[type].get(id);
    let isNew = false;
    if (!unit) {
      unit = this._createUnit(type);
      if (unit) {
        this._units[type].set(id, unit);
        isNew = true;
      }
    }
    if (unit) {
      const classId = view.getUint32(0x04, true);
      const mode = view.getUint32(0x0C, true);
      const posX = view.getInt16(0xD4, true);
      const posY = view.getInt16(0xD6, true);
      const flags = view.getUint32(0x124, true);
      const flagsEx = view.getUint32(0x128, true);
      const changed = isNew || unit.type !== actualType || unit.classId !== classId ||
        unit.id !== id || unit.mode !== mode || unit.posX !== posX || unit.posY !== posY ||
        unit.flags !== flags || unit.flagsEx !== flagsEx;

      if (changed) {
        unit.type = actualType;
        unit.classId = classId;
        unit.id = id;
        unit.mode = mode;
        unit.posX = posX;
        unit.posY = posY;
        unit.flags = flags;
        unit.flagsEx = flagsEx;
        unit._address = currentPtr;
      }
      unit._valid = true;
      if (isNew) this.emit('unitAdded', unit, type);
      if (changed) unit.emit('update', unit);
    }

    seen.add(id);
    const nextPtr = view.getBigUint64(0x158, true);
    if (nextPtr === currentPtr) {
      this._warnChainIssue(type, bucket, currentPtr, 'self-referential unitNext');
      return 0n;
    }
    return nextPtr;
  }

  _scanChain(ptr, type, bucket, seen) {
    let currentPtr = ptr;
    let traversed = 0;
    const visitedPtrs = new Set();

    while (currentPtr !== 0n) {
        if (visitedPtrs.has(currentPtr)) {
          this._warnChainIssue(type, bucket, currentPtr, 'cycle detected');
          break;
        }
        visitedPtrs.add(currentPtr);

        if (++traversed > MAX_CHAIN_NODES) {
          this._warnChainIssue(type, bucket, currentPtr, `traversal cap ${MAX_CHAIN_NODES} reached`);
          break;
        }

        let changed;
        try {
          // Direct Unit pointer models contain the data needed by overlays.
          // Recursing through every room, skill, and item chain on every tick
          // holds the game lock long enough to destroy the game's frame rate.
          changed = this._cursor.$load(currentPtr, 1, 1);
        } catch (e) {
          this._warnChainIssue(type, bucket, currentPtr, `cursor load failed: ${e?.message ?? e}`);
          break;
        }

        const id = this._cursor.id;

        let unit = this._units[type].get(id);
        let isNew = false;
        if (!unit) {
          unit = this._createUnit(type);
          if (unit) {
            this._units[type].set(id, unit);
            isNew = true;
          }
        }

        if (unit) {
          if (changed || isNew) this._cursor.$toObject(unit);
          unit._valid = true;
          if (isNew) this.emit('unitAdded', unit, type);
          unit.emit('update', this._cursor);
        }

        seen.add(id);
        const nextPtr = this._cursor.unitNext;
        if (nextPtr === currentPtr) {
          this._warnChainIssue(type, bucket, currentPtr, 'self-referential unitNext');
          break;
        }
        currentPtr = nextPtr;
    }
  }

  _warnChainIssue(type, bucket, ptr, reason) {
    const now = Date.now();
    if (this._chainIssueWindowStartMs === 0 || now - this._chainIssueWindowStartMs > 10000) {
      this._chainIssueWindowStartMs = now;
      this._chainIssueCount = 0;
    }
    this._chainIssueCount++;
    if (!this._riskCircuitTripped && this._chainIssueCount >= 8) {
      this._riskCircuitTripped = true;
      if (this._logRiskCircuit) {
        this._logError('[ObjectManager] risk circuit tripped, disabling risky features for this session');
      }
    }

    if (!this._logChainIssues) return;
    if (now - this._lastChainWarnMs < 5000) return;
    this._lastChainWarnMs = now;
    this._logInfo(
      `[ObjectManager] guarded unit-chain break: type=${type} bucket=${bucket} ptr=0x${ptr.toString(16)} reason=${reason}`,
    );
  }

  _createUnit(type) {
    let unit;
    switch (type) {
      case UnitTypes.Player:
        unit = new Player(); break;
      case UnitTypes.Monster:
        unit = new Monster(); break;
      case UnitTypes.Object:
        unit = new GameObject(); break;
      case UnitTypes.Missile:
        unit = new Missile(); break;
      case UnitTypes.Item:
        unit = new Item(); break;
      case UnitTypes.Tile:
        unit = new RoomTile(); break;
      default:
        return null;
    }
    UnitModel.initSnapshot(unit);
    return unit;
  }
}

module.exports = { ObjectManager };
