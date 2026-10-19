package main

import (
	"fmt"
	"strings"
)

// renderHTML writes one self-contained page: inline CSS, inline SVG, a
// small inline script for tooltips; no external resources.
func renderHTML(secs []section) string {
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>clifr benchmark report</title>
<style>
:root {
  color-scheme: light;
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11,11,11,0.10);
  --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a; --s4: #eda100; --s5: #8b5fd0; --base: #898781;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --page: #0d0d0d; --surface: #1a1a19; --ink: #ffffff; --ink2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10);
    --s1: #3987e5; --s2: #d95926; --s3: #199e70; --s4: #c98500; --s5: #9a73dd; --base: #898781;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --page: #0d0d0d; --surface: #1a1a19; --ink: #ffffff; --ink2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10);
  --s1: #3987e5; --s2: #d95926; --s3: #199e70; --s4: #c98500; --s5: #9a73dd; --base: #898781;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--ink);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1000px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 26px; margin: 8px 0 4px; }
h2 { font-size: 20px; margin: 40px 0 8px; padding-top: 8px; border-top: 1px solid var(--grid); }
h3 { font-size: 16px; margin: 28px 0 8px; }
p, li { color: var(--ink2); max-width: 75ch; }
nav { font-size: 14px; color: var(--ink2); }
nav a { color: var(--ink2); margin-right: 12px; }
.tablewrap { overflow-x: auto; margin: 12px 0; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); }
table { border-collapse: collapse; font-size: 13px; width: 100%; }
th, td { padding: 6px 10px; border-bottom: 1px solid var(--grid); text-align: left; vertical-align: top; }
th { color: var(--ink2); font-weight: 600; white-space: nowrap; }
td:first-child { white-space: nowrap; }
td.n { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
tr:last-child td { border-bottom: 0; }
.note { font-size: 13px; color: var(--muted); margin: 4px 0 16px; }
figure { margin: 16px 0; padding: 12px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; display: inline-block; max-width: 100%; }
figure.small { margin-right: 12px; }
figcaption { font-size: 13px; color: var(--ink2); margin-top: 4px; }
svg.chart { max-width: 100%; height: auto; display: block; }
svg text { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
.ax { fill: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
.lbl { fill: var(--ink2); font-size: 12px; }
.val { fill: var(--ink); font-size: 11px; font-variant-numeric: tabular-nums; }
.grid { stroke: var(--grid); stroke-width: 1; }
.axis { stroke: var(--axis); stroke-width: 1; }
.ref { stroke: var(--ink2); stroke-width: 1; stroke-dasharray: 4 3; }
.whisker { stroke: var(--ink2); stroke-width: 1.5; fill: none; }
.maxtick { stroke: var(--ink2); stroke-width: 2; }
.line { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
.ringed { stroke: var(--surface); stroke-width: 2; }
.dot { fill: var(--ink); stroke: var(--surface); stroke-width: 2; }
[data-tip] { cursor: default; outline: none; }
[data-tip]:hover, [data-tip]:focus { opacity: 0.8; }
#tip { position: fixed; pointer-events: none; display: none; max-width: 320px; padding: 6px 9px;
  background: var(--surface); color: var(--ink); border: 1px solid var(--border); border-radius: 6px;
  font-size: 12px; white-space: pre-line; box-shadow: 0 2px 8px rgba(0,0,0,0.15); z-index: 10; }
</style></head><body><main>
<h1>clifr benchmark report</h1>
`)
	b.WriteString("<nav>")
	for i, s := range secs {
		if s.Level == 2 {
			fmt.Fprintf(&b, `<a href="#s%d">%s</a>`, i, esc(s.Title))
		}
	}
	b.WriteString("</nav>\n")
	for i, s := range secs {
		fmt.Fprintf(&b, "<h%d id=\"s%d\">%s</h%d>\n", s.Level, i, esc(s.Title), s.Level)
		for _, bl := range s.Blocks {
			switch {
			case bl.Para != "":
				fmt.Fprintf(&b, "<p>%s</p>\n", esc(bl.Para))
			case bl.Items != nil:
				b.WriteString("<ul>")
				for _, it := range bl.Items {
					fmt.Fprintf(&b, "<li>%s</li>", esc(it))
				}
				b.WriteString("</ul>\n")
			case bl.Table != nil:
				b.WriteString(tableHTML(bl.Table))
			case bl.Chart != "":
				cls := ""
				if strings.Contains(bl.Chart, `viewBox="0 0 400 `) {
					cls = ` class="small"`
				}
				fmt.Fprintf(&b, "<figure%s>%s<figcaption>%s</figcaption></figure>\n", cls, bl.Chart, esc(bl.Caption))
			}
		}
	}
	b.WriteString(`</main><div id="tip" role="tooltip"></div>
<script>
(function () {
  var tip = document.getElementById('tip');
  function show(e, el) {
    tip.textContent = el.getAttribute('data-tip');
    tip.style.display = 'block';
    var r = el.getBoundingClientRect();
    var x = e && e.clientX !== undefined ? e.clientX : r.left + r.width / 2;
    var y = e && e.clientY !== undefined ? e.clientY : r.top;
    var w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, x + 12)) + 'px';
    tip.style.top = Math.max(8, y - h - 12) + 'px';
  }
  function hide() { tip.style.display = 'none'; }
  document.querySelectorAll('[data-tip]').forEach(function (el) {
    el.addEventListener('pointermove', function (e) { show(e, el); });
    el.addEventListener('pointerleave', hide);
    el.addEventListener('focus', function () { show(null, el); });
    el.addEventListener('blur', hide);
  });
})();
</script>
</body></html>
`)
	return b.String()
}

func tableHTML(t *table) string {
	var b strings.Builder
	b.WriteString(`<div class="tablewrap"><table><thead><tr>`)
	for _, h := range t.Head {
		fmt.Fprintf(&b, "<th>%s</th>", esc(h))
	}
	b.WriteString("</tr></thead><tbody>")
	for _, row := range t.Rows {
		b.WriteString("<tr>")
		for i, c := range row {
			cls := ""
			if i > 0 && !t.KV && looksNumeric(c) {
				cls = ` class="n"`
			}
			fmt.Fprintf(&b, "<td%s>%s</td>", cls, esc(c))
		}
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table></div>\n")
	if t.Note != "" {
		fmt.Fprintf(&b, "<p class=\"note\">%s</p>\n", esc(t.Note))
	}
	return b.String()
}

func numericColumn(t *table, col int) bool {
	for _, row := range t.Rows {
		if col < len(row) && !looksNumeric(row[col]) {
			return false
		}
	}
	return true
}

func looksNumeric(s string) bool {
	if s == "" || s == "—" {
		return true
	}
	c := s[0]
	return c == '+' || c == '-' || (c >= '0' && c <= '9')
}

// renderMarkdown writes the summary version: the same sections without charts.
func renderMarkdown(secs []section) string {
	var b strings.Builder
	b.WriteString("# clifr benchmark report\n\n")
	for _, s := range secs {
		fmt.Fprintf(&b, "%s %s\n\n", strings.Repeat("#", s.Level), s.Title)
		for _, bl := range s.Blocks {
			switch {
			case bl.Para != "":
				b.WriteString(bl.Para + "\n\n")
			case bl.Items != nil:
				for _, it := range bl.Items {
					b.WriteString("- " + it + "\n")
				}
				b.WriteString("\n")
			case bl.Table != nil:
				b.WriteString(tableMD(bl.Table))
			}
		}
	}
	b.WriteString("Charts: see report.html.\n")
	return b.String()
}

func tableMD(t *table) string {
	var b strings.Builder
	cell := func(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
	b.WriteString("|")
	for _, h := range t.Head {
		b.WriteString(" " + cell(h) + " |")
	}
	b.WriteString("\n|")
	for i := range t.Head {
		if i > 0 && !t.KV && numericColumn(t, i) {
			b.WriteString("---:|")
		} else {
			b.WriteString("---|")
		}
	}
	b.WriteString("\n")
	for _, row := range t.Rows {
		b.WriteString("|")
		for _, c := range row {
			b.WriteString(" " + cell(c) + " |")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	if t.Note != "" {
		b.WriteString("_" + t.Note + "_\n\n")
	}
	return b.String()
}
