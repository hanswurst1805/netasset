# NetAsset Design System

Grün auf Hell, mit klarer Kante. Referenz-Implementierung: [design-system.html](design-system.html).

## Prinzipien

- Helle Fläche, ein Grünton als Handlungsfarbe (Buttons, Links, aktive Zustände).
- Schrift durchgehend Arial, Hierarchie über Gewicht statt über verschiedene Schriften.
- Boxen mit gerundeten Ecken (8 / 14 / 22 px), dezente Schatten statt harter Kante.
- Statusfarben (OK / Warnung / Kritisch / Offline) sind von der Akzentfarbe getrennt und
  ausschließlich für Zustände reserviert.
- Jede Farbe existiert als Light- und Dark-Variante über CSS Custom Properties.

## Farbtokens

### Basis

| Token | Light | Dark | Verwendung |
|---|---|---|---|
| `--bg` | `#F5F9F6` | `#0D1310` | Seiten-Untergrund |
| `--surface` | `#FFFFFF` | `#141B16` | Karten, Panels |
| `--surface-sunken` | `#EEF4F0` | `#101613` | Tabellenkopf, eingesenkte Flächen |
| `--border` | `#DBE6DF` | `#263029` | Trennlinien, Kartenrahmen |
| `--border-strong` | `#C3D3C9` | `#354137` | Eingabefelder, betonte Rahmen |
| `--text` | `#121712` | `#E9F1EB` | Überschriften, Primärtext |
| `--text-secondary` | `#56635B` | `#A3B0A6` | Fließtext, Metadaten |
| `--text-muted` | `#8A968E` | `#77857B` | Labels, Captions, Platzhalter |

### Grünskala (Akzent)

| Token | Light | Dark | Verwendung |
|---|---|---|---|
| `--green-900` | `#0E3B26` | `#B9E7C9` | Höchster Kontrast, sparsam |
| `--green-700` | `#176B41` | `#4CC886` | Primärfarbe (Buttons, Links) |
| `--green-600` | `#1E8A54` | `#3FBE7C` | Hover-Zustand |
| `--green-500` | `#2AA868` | `#34A96D` | Fokus-Ring |
| `--green-100` | `#E2F1E7` | `#1B3226` | Flächen, Fokus-Hintergrund |
| `--green-050` | `#EFF7F1` | `#16261C` | Hover-Hintergrund (sekundäre Buttons) |

### Statusfarben

| Token | Light | Dark | Bedeutung |
|---|---|---|---|
| `--status-ok` / `-bg` | `#1E8A54` / `#E2F1E7` | `#4CC886` / `#16311F` | Online, erfolgreich |
| `--status-warn` / `-bg` | `#966A11` / `#FBF0D9` | `#E0B84C` / `#35290F` | Aufmerksamkeit nötig |
| `--status-crit` / `-bg` | `#A23B31` / `#FAE4E0` | `#E48678` / `#3A1712` | Kritisch, Fehler |
| `--status-off` / `-bg` | `#6B7670` / `#EAEEEB` | `#8E9A92` / `#1C2521` | Offline, inaktiv |

## Typografie

Schriftstapel: `Arial, "Helvetica Neue", Helvetica, sans-serif`. Hierarchie ausschließlich
über Gewicht, Größe und Buchstabenabstand — keine Zweitschrift.

| Rolle | Größe | Gewicht | Sonstiges |
|---|---|---|---|
| Display | 34px | 900 | `letter-spacing: -0.01em` |
| H2 | 21px | 800 | |
| H3 | 16px | 700 | |
| Fließtext | 14px | 400 | Farbe `--text-secondary` |
| Label / Caption | 12px | 700 | Uppercase, `letter-spacing: 0.08em`, Farbe `--text-muted` |

## Radius & Abstand

| Token | Wert | Verwendung |
|---|---|---|
| `--radius-sm` | 8px | Buttons, Inputs, Badges |
| `--radius-md` | 14px | Karten, Tabellen, Alerts |
| `--radius-lg` | 22px | Große Flächen, Hero-Boxen |
| `--space-1`…`--space-8` | 4 / 8 / 12 / 16 / 24 / 32 / 48 / 64px | Konsistente Abstandsskala für Gaps und Padding |

## Komponenten

- **Buttons**: `btn-primary` (gefüllt, Grün 700), `btn-secondary` (Outline), `btn-ghost`
  (ohne Rahmen, für sekundäre Aktionen), `btn-danger` (Outline in Kritisch-Rot),
  `btn-disabled`.
- **Karten (`ds-card`)**: weiße Fläche, `--radius-md`, dezenter Schatten (`--shadow-card`).
  Für Kennzahlen (`ds-card-stat-*`) und Asset-Kurzansichten (`ds-asset-card`).
- **Badges**: `badge-ok` / `badge-warn` / `badge-crit` / `badge-off`, mit farbigem Punkt
  vor dem Label. Ausschließlich für Zustand, nicht als generelle Hervorhebung.
- **Formulare**: Label immer als Uppercase-Caption über dem Feld, Fokus-Zustand über
  `--green-600`-Rahmen plus `--green-100`-Glow.
- **Tabellen**: Kopfzeile auf `--surface-sunken`, Zahlen mit `font-variant-numeric:
  tabular-nums`, horizontal scrollbar in eigenem Container statt Seiten-Scroll.
- **Alerts**: farbiger Rahmen plus getönter Hintergrund je Statusfarbe, Titel in der
  jeweiligen Statusfarbe.

## Theming

Alle Tokens sind CSS Custom Properties auf `:root`. Der Dark Mode greift über
`@media (prefers-color-scheme: dark)` sowie `:root[data-theme="dark"]` /
`:root[data-theme="light"]`, damit ein manueller Theme-Umschalter die
Systemeinstellung übersteuern kann. Komponenten referenzieren ausschließlich Tokens,
nie feste Hex-Werte.

## Nutzung im Frontend

Die Tokens lassen sich 1:1 als CSS-Variablen in `dashboard/src/index.css` übernehmen
oder als Tailwind-Theme-Erweiterung (`tailwind.config`) mappen. Die HTML-Referenz
(`design-system.html`) dient als visuelle Quelle der Wahrheit beim Abgleich neuer
Komponenten.
