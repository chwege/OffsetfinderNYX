# D2R Patch-Offsets - 2026-08-18

## Patch-Fingerabdruck

- D2R executable hash: `0x6A6B974EE2F4F2D0`
- NYX signature hash des bestaetigten Laufs: `0x79DF4F27`
- Image size: `0x02789000`
- Ergebnis des internen Scanners: `29/29`
- Diagnosemodus: read-only; keine Retcheck-Aufrufe und keine Spielzustandsaenderungen

Die Werte sind RVAs relativ zur Basisadresse von `D2R.exe`. Sie sind keine absoluten
Prozessadressen.

## Externe Offset-Liste

```rust
let unit_table  = 0x01EAD470;
// OverlayTool convention: automap flag; find_offsets() subtracts 0xA.
let ui_offset   = 0x01EBD162;
let expansion   = 0x01E00508;
let hover       = 0x01E010A0;
let roster      = 0x01EC3780;
let panels      = 0x01E17E60;
let keybindings = 0x019D55B4;
```

| Name | Neues RVA | Validierung |
| --- | ---: | --- |
| `unit_table` | `0x01EAD470` | Eindeutiger Code-Treffer und sechs Unit-Typen strukturell bestaetigt |
| `ui_offset` | `0x01EBD162` | OverlayTool-Konvention: Automap-Flag bei MenuStates-Basis `0x01EBD158` plus `0xA` |
| `expansion` | `0x01E00508` | Eindeutiger semantischer Code-Treffer |
| `hover` | `0x01E010A0` | Eindeutiger semantischer Code-Treffer |
| `roster` | `0x01EC3780` | Eindeutiger Roster-Zugriff |
| `panels` | `0x01E17E60` | Eindeutiger Panel-Manager-Zugriff |
| `keybindings` | `0x019D55B4` | Passender `Game Chat`-Tabelleneintrag; Tabellenbasis `0x019D55A0` durch Spielcode referenziert |

Die alten Benutzerwerte wurden nur zum Vergleich protokolliert. Sie wurden weder als
Fallback verwendet noch zur Berechnung der neuen Werte addiert oder verschoben.

Das interne NYX-Feld `Reference_UIOffset` bezeichnet dagegen direkt den Anfang von
`MenuStates` bei `0x01EBD158`. Dieser Unterschied ist absichtlich in der Liste der 29
NYX-Offsets weiter unten sichtbar.

## Alle 29 NYX-Offsets

| Name | RVA |
| --- | ---: |
| `D2Allocator` | `0x01F1D600` |
| `kCheckData` | `0x01D57088` |
| `DRLG_AllocLevel` | `0x002DFA60` |
| `DRLG_InitLevel` | `0x00252810` |
| `ROOMS_AddRoomData` | `0x002365D0` |
| `GetLevelDef` | `0x008FBCD0` |
| `s_automapLayerLink` | `0x01EBD2A8` |
| `s_currentAutomapLayer` | `0x01EBF2E0` |
| `ClearLinkedList` | `0x0005ED20` |
| `AUTOMAP_NewAutomapCell` | `0x000BA1B0` |
| `AUTOMAP_AddAutomapCell` | `0x00BAA540` |
| `Widget::GetScaledPosition` | `0x0065E7A0` |
| `Widget::GetScaledSize` | `0x007C5AD0` |
| `PanelManager::GetScreenSizeX` | `0x00065470` |
| `s_panelManager` | `0x01EE5790` |
| `AutoMapPanel_GetMode` | `0x000B1360` |
| `AutoMapPanel_CreateAutoMapData` | `0x000B05D0` |
| `AutoMapPanel_PrecisionToAutomap` | `0x000B0FB0` |
| `AutoMapPanel_spdwShift` | `0x01EB0510` |
| `sgptDataTbls` | `0x01E03AC0` |
| `DATATBLS_GetAutomapCellId` | `0x0029D110` |
| `s_PlayerUnitIndex` | `0x01EAD46C` |
| `sgptClientSideUnitHashTable` | `0x01EAD470` |
| `GetClientSideUnitHashTableByType` | `0x0006C0A0` |
| `GetServerSideUnitHashTableByType` | `0x0006C0C0` |
| `EncEncryptionKeys` | `0x01DD9E08` |
| `Reference_UIOffset` | `0x01EBD158` |
| `Reference_Expansion` | `0x01E00508` |
| `Reference_Roster` | `0x01EC3780` |

## Funktionsstand

- DLL-Laden und natives Logging: bereit
- Dynamische Offset-Aufloesung: `29/29`
- Client-Unit-Tabelle und lokaler Spieler: read-only bestaetigt
- NYX-Laufzeit in diesem Build: absichtlich deaktiviert/geschuetzt
- Retcheck-V2: nicht bereit
- Geschuetzte Automap-Aufrufe und Reveal: weiterhin blockiert

`kCheckData` wurde gefunden. Das ist jedoch kein Nachweis fuer einen funktionierenden
Retcheck-Bypass. Der Diagnose-Build ruft die geschuetzten Funktionen bewusst nicht auf.

## Ablauf beim naechsten D2R-Patch

1. D2R aktualisieren, starten und einen Charakter ins Spiel laden.
2. `START_PATCH_DIAGNOSE_UND_CACHE.bat` ausfuehren.
3. Im Log den neuen executable hash und `Resolved 29/29 offsets` pruefen.
4. Die sieben externen Werte aus den Struktur-, Pattern- und Code-Referenz-Ergebnissen
   uebernehmen. Alte RVAs niemals als Rechenbasis oder Fallback verwenden.
5. Bei fehlenden Treffern das geaenderte Pattern anhand des neuen Binaercodes erneuern
   und erneut mit Strukturmerkmalen bestaetigen.
6. Erst nach einem sauberen Lauf den Offset-Cache fuer schnelle Starts verwenden.

## Zugehoerige Dateien

- Scannerdefinitionen: `src/offsets.h`
- Strukturresolver und Offset-Cache: `src/offsets.cc`
- Externe Referenzdiagnose: `src/reference_offset_diagnostics.cc`
- Letzter Lauf: `out/install/x64-debug/bin/dolos-native.log`
- Startskript: `out/install/x64-debug/bin/START_PATCH_DIAGNOSE_UND_CACHE.bat`
