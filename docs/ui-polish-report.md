# UI polish — SOC command center

The existing dark SOC is preserved and refined. No new UI library, router, state manager, icon package or backend intelligence was introduced. Public product styling remains independently scoped.

## 1–3. Direction, representative page and observed problems

Solid charcoal surfaces, a muted blue accent, native system typography, readable metadata, restrained borders/radius and clear state labels replace translucent/blurred cards, gradients, pulsing indicators, decorative symbols and low-contrast text. Large numerical metrics remain readable when projected. Classifier scores, normalized anomaly scores, traffic provenance and contextual ATT&CK associations remain distinct.

**Detection Detail** was implemented and rendered first at 1440, 820 and 390 pixels. Its initial mobile render exposed page overflow and navigation taking excessive vertical space. The app shell was corrected with a disclosure menu and a zero-minimum grid column, then the representative page was rerendered and inspected before extending the styles to other pages.

Other issues found: missing CSS-token aliases, ambiguous detection-table score label, no recorded source mode in detection rows, pointer-only row opening, raw lifecycle underscores wrapping badly, missing approved-model identity, unavailable counters rendered as zero, and a replay Sensor crash when `operational_health` lacked `reasons`. These were corrected. The latter has a regression test.

## 4–6. Files, tokens and preserved behavior

See [exact current-turn file inventory](rw4-ui-changed-files.json). UI changes are in `App.tsx`, the existing seven page modules plus Flow Detail, `api/types.ts`, `styles/globals.css`, the new `styles/investigation.css`, and the Sensor regression tests. The product FAQ and two actual-console screenshots were refreshed to reflect RW-4; its architecture, legal drafts and warm-neutral styling remain.

Shared tokens now use solid `background/surface/hover`, primary/secondary/muted text, one blue accent, distinct labeled severity colors, borders, the existing 4/8px spacing scale, restrained radii, system fonts, readable type sizes and a content width. Missing legacy aliases resolve to those tokens. Responsive grids, table scrolling, section headings, source banners, runtime identity and refresh notes use shared styles. No new font/network dependency was added.

Preserved: credential/session behavior; authenticated REST and WebSocket protocols; bounded/deduplicated live-event buffer; routing; server-side filters/pagination; flow links; event scores/evidence; lifecycle/error counters; backend-generated intelligence. Sensor remains read-only. Settings has only endpoint and masked credential configuration, with no model paths, capture controls, shell access or secret display. API reachability is labeled separately from sensor health. Loading remains real, empty/error states remain explicit, and failed polling hides stale data with the time of the last successful update and a Retry action.

## 7–9. Viewports and accessibility

Every requested page was rendered and visually inspected at **1440×1000 desktop**, **820×1000 tablet** and **390×1000 mobile**. All 21 route/viewport checks had **no horizontal page overflow** and no browser page errors. Wide operational tables scroll inside labeled, keyboard-focusable regions. Mobile navigation is an accessible disclosure with `aria-expanded`/`aria-controls`; the active route remains identified. UUIDs, replay identifiers, model identity, timestamps, flow addresses and evidence were inspected in actual records.

Keyboard checks covered the skip link, visible 2px focus outline, mobile menu, navigation, detection opening via a semantic link and flow opening. Headings, tables, field labels, severity text and source labels are retained. Reduced-motion mode reports no active status animation. Token contrast against the card surface: primary text **13.92:1**, secondary **9.48:1**, muted **7.66:1**, links/accent **8.31:1**. This is a targeted check, not an exhaustive assistive-technology or accessibility certification.

## 10–13. Tests and contracts

| Gate | Result |
|---|---|
| Frontend tests | 61 passed, 5 files |
| TypeScript strict | PASS |
| Production build | PASS |
| Backend after RW-4 contract additions | 631 passed, 14 existing warnings |
| Protected science | 23/23 files unchanged |

The backend additions expose approved model identity and live interface as operational provenance required by RW-4. No visual-only endpoint or duplicate frontend model state was added.

Browser interactions used the actual authenticated local backend: detection pagination (1–50 then 51–65), severity/threat filtering, empty results, detail opening, statistical evidence, flow opening, mobile navigation, replay state, API-request failure, disconnected WebSocket and visible keyboard focus. Live-state verification used `SensorService` with a clearly named **synthetic-test0** capture source, an approved bundle, real inference/SQLite/REST and an authenticated WebSocket event. The LIVE state reflects that service path, not a real physical-interface validation.

## 14–16. Screenshots, limitations and unchanged areas

All screenshot records are synthetic PCAP/test-source data processed by real models; no counts or event responses were fabricated in the frontend. This is UI/contract verification, not detection-accuracy evidence.

| Page | Desktop | Tablet | Mobile |
|---|---|---|---|
| Overview | [1440](ui-polish/overview-1440.png) | [820](ui-polish/overview-820.png) | [390](ui-polish/overview-390.png) |
| Detections | [1440](ui-polish/detections-1440.png) | [820](ui-polish/detections-820.png) | [390](ui-polish/detections-390.png) |
| Detection Detail | [1440](ui-polish/detail-1440.png) | [820](ui-polish/detail-820.png) | [390](ui-polish/detail-390.png) |
| Flows | [1440](ui-polish/flows-1440.png) | [820](ui-polish/flows-820.png) | [390](ui-polish/flows-390.png) |
| Sensor | [1440](ui-polish/sensor-1440.png) | [820](ui-polish/sensor-820.png) | [390](ui-polish/sensor-390.png) |
| Intelligence | [1440](ui-polish/intelligence-1440.png) | [820](ui-polish/intelligence-820.png) | [390](ui-polish/intelligence-390.png) |
| Settings | [1440](ui-polish/settings-1440.png) | [820](ui-polish/settings-820.png) | [390](ui-polish/settings-390.png) |

Additional evidence: [LIVE service with synthetic input](ui-polish/live-synthetic-390.png), [flow detail](ui-polish/flow-detail-390.png), [empty filter](ui-polish/empty-390.png), [API unavailable](ui-polish/api-error-390.png), [WebSocket disconnected](ui-polish/disconnected-390.png), [keyboard focus](ui-polish/keyboard-focus-390.png), [browser checks](ui-polish/browser-checks.json), [live/accessibility checks](ui-polish/live-accessibility-checks.json).

Remaining limits: dense tables deliberately require horizontal scrolling on smaller screens. Browser review used Chromium; Safari/Firefox and screen-reader-specific testing remain unperformed. No invented throughput/latency time series was added because the API does not expose those series. Existing historical scientific metrics, algorithms, feature extraction, thresholds, authentication transport, capture implementation and research assets were intentionally left unchanged. Public Privacy and Terms remain **DRAFT FOR REVIEW** with known practices only. No compliance or production-readiness claim was added.

## 17. Git recommendation

After preserving the existing uncommitted baseline, commit RW-4 and UI polish separately. Suggested UI message: `ui: refine SOC hierarchy and responsive operation`. Stage from the exact file inventory; exclude unrelated presentation/research assets and temporary databases. The whole-working-tree `git diff --check` still reports whitespace in pre-existing uncommitted documentation/storage changes; those unrelated lines were not reformatted. No commit was made. Work stops here; RW-5 was not begun.
