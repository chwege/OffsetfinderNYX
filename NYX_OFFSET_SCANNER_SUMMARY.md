# NYX D2R Offset Scanner - Projektzusammenfassung

Stand: 2026-08-19

## Ziel des Forks

Dieser Fork wurde aus `BBnan1987/nyx-d2r-bbnan` mit allen Submodules aufgebaut,
um D2R-Offsets nach einem Patch neu zu finden und strukturell zu pruefen. Alte
Offsetwerte werden nur als Vergleichswerte protokolliert. Sie werden weder als
Laufzeit-Fallback verwendet noch durch eine Patch-Differenz auf neue Werte
umgerechnet.

Der aktuelle Schwerpunkt ist ein sicherer, lesender Diagnosebetrieb:

- dynamisches Finden der NYX-Offsets;
- strukturelle Validierung der Unit-Tabellen;
- Ermittlung der Offsets fuer ein externes Rust-Overlay;
- reproduzierbare Logs und ein patchabhaengiger Offset-Cache;
- kein Aufruf geschuetzter D2R-Funktionen im Diagnoseprofil;
- keine Aenderung des Spielzustands.

## Ausgangsproblem und Crashanalyse

Der urspruengliche Build stuerzte nach der DLL-Injektion ab. Die Disassemblierung
und die Crashadresse zeigten auf das Anti-Tamper-Epilog der Automap-Funktion. Wenn
der Retcheck eine ungueltige oder manipulierte Rueckkehrpruefung erkennt, fuehrt
D2R absichtlich einen Nullzeigerzugriff aus. Der alte Retcheck-Bypass passte nicht
mehr zur geaenderten V2-Struktur des gepatchten Spiels.

Daraufhin wurde der Diagnosepfad schrittweise abgesichert:

- Retcheck-Aufrufe, Hooks und Mutation wurden im sicheren Profil deaktiviert;
- keine Thread-Suspendierung und keine Decrypt-Gadget-Aufrufe;
- lesbare Speicherbereiche werden ueber Regionengrenzen korrekt geprueft;
- Offset- und Unit-Tabellen-Scans laufen read-only;
- Injector und Named-Pipe-Logging liefern eindeutige Lade- und Laufzeitfehler;
- der DLL-Ladepfad wurde mit separatem Probe-Tool diagnostizierbar gemacht;
- ein bereits belegter Log-Pipe-Name wird sauber gemeldet;
- ImGui erhaelt eine gueltige Displaygroesse und einen eigenen Frame-Heartbeat.

## Dynamischer NYX-Scanner

Der Scanner verarbeitet 29 NYX-Offsets. Pattern-Treffer werden nicht blind
uebernommen, sondern je nach Offset durch weitere Merkmale bestaetigt:

- eindeutige Code-Signaturen und RIP-relative Ziele;
- Funktionsprologe und Call-Ziele;
- lesbare Datenbereiche innerhalb des D2R-Abbilds;
- spaete fokussierte Rescans fuer erst nach Spielbeitritt initialisierte Daten;
- strukturbezogene Resolver fuer Unit- und UI-Daten;
- Cache nur nach einem vollstaendig validierten Diagnoselauf.

Der bestaetigte Lauf fuer den D2R-Patch mit Executable-Hash
`0x6A6B974EE2F4F2D0` ergab:

- `29/29` effektive NYX-Offsets;
- `25/25` Core-Offsets;
- keine fehlenden Eintraege;
- lokale Spieleridentitaet ueber die Client-Unit-Tabelle;
- abschliessenden Offset-Cache fuer schnelle Folgestarts.

Die vollstaendige Liste steht in [PATCH_OFFSETS_2026-08-18.md](PATCH_OFFSETS_2026-08-18.md).

## Unit-Tabellen

Der alte feste Unit-Tabellenwert wurde nicht weiterverwendet. Der neue Scanner
findet zwei benachbarte, jeweils konsistente Bloecke:

- erster Block: `0x01EAD470`;
- zweiter Block: `0x01EAEC70`;
- Abstand: `0x1800`;
- je Block sechs Unit-Typen mit jeweils 128 Hash-Buckets.

Der erste Block wurde durch Codebezug, Player-Index-Nachbarschaft, Unit-Typen,
verkettete Nodes und gueltige Live-Daten als Client-Tabelle bestaetigt. Im finalen
Verifikationslauf enthielt er 360 gueltige Nodes. Karten- oder Gebietswechsel
aendern den RVA der Tabelle nicht; sie aendern nur die enthaltenen Units und
verketteten Eintraege.

## Offset-Scanner fuer OverlayTool

Das externe Rust-Projekt OverlayTool verwendet sieben patchabhaengige RVAs.
NYX ermittelt sie mit semantischen Patterns und Strukturpruefungen, nicht durch
Fortschreiben alter Werte.

```rust
let unit_table  = 0x01EAD470;
let ui_offset   = 0x01EBD162;
let expansion   = 0x01E00508;
let hover       = 0x01E010A0;
let roster      = 0x01EC3780;
let panels      = 0x01E17E60;
let keybindings = 0x019D55B4;
```

Validierung:

| Offset | Methode |
| --- | --- |
| `unit_table` | eindeutiger Codebezug plus Sechs-Typen-Struktur und Node-Pruefung |
| `ui_offset` | 32-Byte-Flagfeld plus zwei unabhaengige Code-Writer |
| `expansion` | eindeutiges semantisches Code-Pattern |
| `hover` | eindeutiges semantisches Code-Pattern |
| `roster` | eindeutiger Roster-Zugriff |
| `panels` | eindeutiger Panel-Manager-Zugriff |
| `keybindings` | `Game Chat`-Tabelleneintrag plus Code-Referenz auf die Tabellenbasis |

NYX bezeichnet mit `Reference_UIOffset = 0x01EBD158` direkt den Anfang des
32-Byte-`MenuStates`-Feldes. OverlayTool erwartet dagegen das Automap-Flag bei
`Basis + 0xA`, also `0x01EBD162`, und zieht in `find_offsets()` wieder `0xA` ab.

Das Overlay wurde mit diesen sieben Werten neu gebaut und praktisch als
funktionsfaehig bestaetigt. Zwei weitere Overlay-Werte sind davon unabhaengig und
noch nicht Teil dieses Scanners:

- `last_game_name`;
- `skill_keys`.

## Retcheck und Automap

`kCheckData` wird fuer den aktuellen Patch bei `0x01D57088` gefunden. Das ist
jedoch kein Retcheck-Bypass.

Der V2-Adapter validiert nur lesend die gefundene Struktur und fuehrt einen
Dry-Run durch. Er ruft weder Allocator, Submit-Funktion, Dispatcher noch
geschuetzte Spielmethoden auf. Deshalb bleiben folgende NYX-Bindings blockiert:

- `automapGetMode`;
- `worldToAutomap`;
- `revealLevel`;
- weitere schreibende oder geschuetzte Automap-Pfade.

Als sichere Alternative rendert der Demo-Pfad eine lokale Uebersichtskarte aus
gelesenen Room-/Level-Daten. Player, Monster, Objekte, Missiles, Items und Tiles
werden ueber die vollstaendige Client-Unit-Tabelle gelesen.

## Wichtige Quellbereiche

- `src/offsets.h`: Patterndefinitionen der 29 NYX-Offsets;
- `src/offsets.cc`: Scanner, Cache, fokussierte Rescans und Strukturresolver;
- `src/unit_table_diagnostics.*`: Unit-Tabellen-Modell und Validierung;
- `src/reference_offset_diagnostics.*`: sieben Overlay-Referenzscanner;
- `src/d2r_feature_check.*`: read-only Funktionsstatus;
- `src/retcheck_v2_adapter.*`: struktureller Retcheck-V2-Dry-Run;
- `tools/simple_injector.cc`: Injektion, Pipe-Logging und Diagnosemodus;
- `tools/dll_load_probe.cc`: isolierte DLL-Ladediagnose;
- `tools/offset_xref_analyzer.cc`: Offline-Xref-Analyse einer angegebenen PE-Datei;
- `patches/nyx-local.patch`: notwendige Aenderungen im NYX-Submodule.

## Build aus einem frischen Clone

Voraussetzungen:

- Windows x64;
- Visual Studio mit Desktop-C++-Werkzeugen;
- CMake und Ninja;
- Git mit Submodule-Unterstuetzung.

```bat
git clone --recurse-submodules <DEINE-GITHUB-URL>
cd <REPOSITORY>
apply_nyx_patch.bat

cmake --preset x64-debug ^
  -DNYX_D2R_SAFE_DIAGNOSTIC_MODE=ON ^
  -DNYX_D2R_SAFE_NO_THREAD_SUSPEND=ON ^
  -DNYX_D2R_SAFE_NO_DECRYPT_TOUCH=ON ^
  -DNYX_D2R_SAFE_READ_ONLY_RUNTIME=ON ^
  -DNYX_D2R_FAST_DIAGNOSTIC=ON

cmake --build out\build\x64-debug --target nyx.d2r --parallel 8
cmake --install out\build\x64-debug --prefix out\install\x64-debug
```

Lokale Signierung ist optional. Private PFX/PVK-Dateien und Kennwoerter duerfen
nicht in das Repository aufgenommen werden.

## Auf GitHub veroeffentlichen

Der erzeugte Exportordner ist bereits ein sauberes Git-Repository mit einem
`main`-Branch und einem Start-Commit. Nach dem Erstellen eines leeren GitHub-
Repositories genuegen folgende Befehle im Exportordner:

```bat
git remote add origin https://github.com/<BENUTZER>/<REPOSITORY>.git
git push -u origin main
```

Das GitHub-Repository darf beim Anlegen nicht automatisch mit README, Lizenz oder
`.gitignore` initialisiert werden, da diese Dateien bereits im Export enthalten
sind.

## Vorgehen beim naechsten D2R-Patch

1. D2R aktualisieren und einen Charakter ins Spiel laden.
2. Einen Full-Patch-Diagnoselauf ohne alten Offset-Cache starten.
3. Executable-Hash und `Resolved 29/29 offsets` im Log pruefen.
4. Unit-Tabelle und UI-Feld strukturell bestaetigen.
5. Fuer OverlayTool alle sieben Scannerergebnisse pruefen. Mehrdeutige Treffer
   muessen durch Code-Referenzen oder Datenstrukturmerkmale reduziert werden.
6. Geaenderte Patterns anhand des neuen Binaercodes erneuern. Alte RVAs nie als
   Berechnungsbasis oder Laufzeit-Fallback verwenden.
7. Erst nach einem vollstaendig validierten Lauf den neuen Cache verwenden.
8. Die Patch-Dokumentation mit Executable-Hash und neuen RVAs aktualisieren.

## Repository-Hygiene

Der GitHub-Export enthaelt nur Quellcode, Dokumentation und reproduzierbare
Patches. Ausgeschlossen sind:

- `out/`, CMake-/Ninja-Builds und installierte DLLs;
- Laufzeit-, Injector- und Diagnoselogs;
- Diagnosearchive, Speicherabbilder und Offset-Caches;
- lokale Zertifikate und private Schluessel;
- Visual-Studio-Caches und Benutzerdateien;
- D2R-Dateien und sonstige Spielbinaries;
- ausgecheckte Multi-GB-Submodule im Hauptrepository.

`vendor/nyx` bleibt ein Git-Submodule auf Revision
`332f82f64ec2f87617c4b372d341e390dbe82de4`. Die lokalen Submodule-Aenderungen
werden reproduzierbar durch `patches/nyx-local.patch` angewendet.

## Sicherheitshinweis

DLL-Injektion und externes Lesen von D2R-Speicher koennen gegen die Regeln des
Spiels verstossen und zu Sanktionen fuehren. Der bereitgestellte Diagnosemodus
vermeidet geschuetzte Aufrufe und Mutation, beseitigt dieses Nutzungsrisiko aber
nicht.
