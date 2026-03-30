/**
 * Compares two scan results to detect new/removed assets and risk changes.
 */

import type { ScanResult, CompareResult } from '../types';

export function compareScans(oldScan: ScanResult, newScan: ScanResult): CompareResult {
  const oldMap = new Map(oldScan.assets.map(a => [a.id, a]));
  const newMap = new Map(newScan.assets.map(a => [a.id, a]));

  const newAssets = newScan.assets.filter(a => !oldMap.has(a.id));
  const removedAssets = oldScan.assets.filter(a => !newMap.has(a.id));

  const riskChanges: CompareResult['riskChanges'] = [];
  for (const [id, newAsset] of newMap) {
    const oldAsset = oldMap.get(id);
    if (oldAsset && oldAsset.riskScore !== newAsset.riskScore) {
      riskChanges.push({
        asset: newAsset,
        oldScore: oldAsset.riskScore,
        newScore: newAsset.riskScore,
      });
    }
  }

  return {
    newAssets,
    removedAssets,
    riskChanges,
    summary: {
      added: newAssets.length,
      removed: removedAssets.length,
      changed: riskChanges.length,
    },
  };
}
