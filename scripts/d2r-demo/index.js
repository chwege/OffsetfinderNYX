'use strict';

import { ObjectManager, UnitTypes, DebugPanel, revealLevel } from 'nyx:d2r';
import { RuntimeModes, setRuntimeMode, getRuntimeMode, isActiveMutationEnabled } from 'nyx:d2r';
import { withGameLock } from 'nyx:memory';
import { Markers } from './markers.js';
import { ExitMarkers } from './exit-markers.js';
import { resolveLoggingConfig } from './lib/logging-config.js';
import { createDiagnosticLogger } from './lib/diagnostic-logger.js';

const processBinding = internalBinding('process');

// Keep the control build read-only and isolate UI responsiveness from scanning.
const ENABLE_ACTIVE_MUTATION = false;
const ENABLE_READ_ONLY_UNIT_SCAN = true;
const ENABLE_READ_ONLY_FULL_SCAN = true;
const DEBUG_PANEL_REFRESH_INTERVAL_MS = 100;
const OBJECT_SCAN_INTERVAL_MS = 20;

const LOGGING = resolveLoggingConfig({
  processBinding,
});
const DEBUG_LOG = LOGGING.debugLog;
const UNIT_EXPLORER_PERF_LOG = LOGGING.unitExplorer.perfEnabled;
const UNIT_EXPLORER_PERF_LOG_FILE = LOGGING.unitExplorer.filePath;
const scriptLogger = createDiagnosticLogger({
  name: 'Script',
  enabled: LOGGING.script.enabled,
  minLevel: LOGGING.script.minLevel,
  toConsole: LOGGING.script.toConsole,
  toFile: LOGGING.script.toFile,
  filePath: LOGGING.script.filePath,
});
const unitExplorerLogger = createDiagnosticLogger({
  name: 'UnitExplorerPerf',
  enabled: LOGGING.unitExplorer.perfEnabled,
  minLevel: LOGGING.unitExplorer.minLevel,
  toConsole: LOGGING.unitExplorer.toConsole,
  toFile: LOGGING.unitExplorer.toFile,
  filePath: LOGGING.unitExplorer.filePath,
});
const objectManagerLogger = createDiagnosticLogger({
  name: 'ObjectManager',
  enabled: LOGGING.objectManager.enabled,
  minLevel: LOGGING.objectManager.minLevel,
  toConsole: LOGGING.objectManager.toConsole,
  toFile: LOGGING.objectManager.toFile,
  filePath: LOGGING.objectManager.filePath,
});

function unitExplorerPerfLogger(...args) {
  unitExplorerLogger.info(...args);
}

function debugLog(...args) {
  if (DEBUG_LOG) {
    scriptLogger.debug(...args);
  }
}

try {
  if (UNIT_EXPLORER_PERF_LOG) {
    unitExplorerLogger.info(`session_start log_file=${UNIT_EXPLORER_PERF_LOG_FILE}`);
    if (LOGGING.sourcePath) {
      unitExplorerLogger.info(`config_source=${LOGGING.sourcePath}`);
    }
  }
  const objMgr = new ObjectManager({
    logChainIssues: LOGGING.objectManager.chainWarnings,
    logRiskCircuit: LOGGING.objectManager.riskCircuit,
    logInfo: (...args) => objectManagerLogger.info(...args),
    logError: (...args) => objectManagerLogger.error(...args),
  });
  const debugPanel = new DebugPanel(objMgr, {
    perfLog: UNIT_EXPLORER_PERF_LOG,
    logger: unitExplorerPerfLogger
  });
  const markers  = new Markers(objMgr);
  const exitMarkers = new ExitMarkers(objMgr, {
    perf: LOGGING.exitMarkers,
  });
  const desiredRuntimeMode = ENABLE_ACTIVE_MUTATION ? RuntimeModes.ActiveMutation : RuntimeModes.ReadOnlySafe;
  if (!setRuntimeMode(desiredRuntimeMode)) {
    console.warn(`[RuntimeMode] Failed to set mode: ${desiredRuntimeMode}`);
  }
  if (DEBUG_LOG) {
    scriptLogger.info('debug logging enabled');
    if (LOGGING.sourcePath) {
      scriptLogger.info(`config_source=${LOGGING.sourcePath}`);
    }
  }
  debugLog(`[RuntimeMode] ${getRuntimeMode()}`);
  const liveObjectScanning = isActiveMutationEnabled();
  if (!liveObjectScanning) {
    console.warn('Mutation features disabled in read_only_safe mode');
    console.warn(ENABLE_READ_ONLY_UNIT_SCAN
      ? 'Full unit scanning disabled; using incremental read-only bucket updates'
      : 'Unit scanning paused for UI responsiveness control build');
  }

  let lastIncrementalCycle = 0;
  const tickIncrementalScan = () => {
    if (!objMgr.tickIncrementalClient()) return;
    if (objMgr.incrementalCycleCount === lastIncrementalCycle) return;

    lastIncrementalCycle = objMgr.incrementalCycleCount;
    exitMarkers.tick();
    debugLog(
      `[IncrementalScan] cycle=${lastIncrementalCycle} players=${objMgr.getUnits(UnitTypes.Player).size} ` +
      `monsters=${objMgr.getUnits(UnitTypes.Monster).size} items=${objMgr.getUnits(UnitTypes.Item).size} ` +
      `objects=${objMgr.getUnits(UnitTypes.Object).size} missiles=${objMgr.getUnits(UnitTypes.Missile).size} ` +
      `tiles=${objMgr.getUnits(UnitTypes.Tile).size}`,
    );
  };

  const tickReadOnlyScan = () => {
    if (!ENABLE_READ_ONLY_FULL_SCAN) {
      tickIncrementalScan();
      return;
    }
    objMgr.tickFullClientReadOnly();
    exitMarkers.tick();
  };

  if (liveObjectScanning) {
    objMgr.tick();
  } else if (ENABLE_READ_ONLY_UNIT_SCAN) {
    tickReadOnlyScan();
  }

  const players = objMgr.getUnits(UnitTypes.Player);
  const monsters = objMgr.getUnits(UnitTypes.Monster);
  const items = objMgr.getUnits(UnitTypes.Item);
  const objects = objMgr.getUnits(UnitTypes.Object);
  const missiles = objMgr.getUnits(UnitTypes.Missile);
  const tiles = objMgr.getUnits(UnitTypes.Tile);

  debugLog(`Objects`);
  debugLog(`  Players:  ${players.size}`);
  debugLog(`  Monsters: ${monsters.size}`);
  debugLog(`  Items:    ${items.size}`);
  debugLog(`  Objects:  ${objects.size}`);
  debugLog(`  Missiles: ${missiles.size}`);
  debugLog(`  Tiles:    ${tiles.size}`);

  if (DEBUG_LOG && objMgr.me) {
    debugLog(`\nLocal player: id=${objMgr.me.id} at (${objMgr.me.posX}, ${objMgr.me.posY})`);
    debugLog(JSON.stringify(objMgr.me, (_, v) => typeof v === 'bigint' ? v.toString(16) : v, 2));
  }

  // Show first few monsters
  let count = 0;
  for (const [id, monster] of monsters) {
    if (count >= 5) break;
    if (DEBUG_LOG) {
      debugLog(`  Monster id=${id} classId=${monster.classId} at (${monster.posX}, ${monster.posY}) alive=${monster.isAlive}`);
    }
    count++;
  }

  let revealed_levels = [];
  let revealDisabled = !isActiveMutationEnabled();
  let revealFailureStreak = 0;
  let wasInGame = !!objMgr.me;
  let lastDebugPanelRefresh = 0;
  setInterval(() => {
    const now = Date.now();
    if (liveObjectScanning) {
      objMgr.tick();
      exitMarkers.tick();
    } else if (ENABLE_READ_ONLY_UNIT_SCAN) {
      tickReadOnlyScan();
    }
    if (now - lastDebugPanelRefresh >= DEBUG_PANEL_REFRESH_INTERVAL_MS) {
      debugPanel.refresh();
      lastDebugPanelRefresh = now;
    }

    if (!revealDisabled && !isActiveMutationEnabled()) {
      revealDisabled = true;
      console.warn('Runtime mode changed to read_only_safe; disabling reveal');
    }

    if (!revealDisabled && typeof objMgr.isRiskCircuitTripped === 'function' && objMgr.isRiskCircuitTripped()) {
      revealDisabled = true;
      console.warn('Reveal circuit breaker enabled for this session; keeping read-only overlays active');
    }

    const me = objMgr.me;
    const inGame = !!me;
    if (inGame !== wasInGame) {
      if (inGame) {
        debugLog('[Transition] Entered game');
      } else {
        debugLog('[Transition] Left game');
      }
      wasInGame = inGame;
    }

    if (!me && revealed_levels.length > 0) {
      debugLog("Resetting revealed levels");
      revealed_levels = [];
      revealFailureStreak = 0;
    }
    if (me && !revealDisabled) {
      const currentLevelId = me.path?.room?.drlgRoom?.level?.id;
      if (currentLevelId !== undefined && !revealed_levels.includes(currentLevelId)) {
        withGameLock(_ => {
          if (revealLevel(currentLevelId)) {
            debugLog(`Revealed level ${currentLevelId}`);
            revealed_levels.push(currentLevelId);
            revealFailureStreak = 0;
          } else {
            revealFailureStreak++;
            if (revealFailureStreak >= 3) {
              revealDisabled = true;
              console.warn('Reveal disabled after repeated failures; continuing in read-only mode');
            }
          }
        });
      }
    }
  }, OBJECT_SCAN_INTERVAL_MS);
} catch (err) {
  console.error(err.message);
  console.error(err.stack);
}
