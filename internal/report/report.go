package report

import (
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/cyb3r3xpl0it/subhawk/internal/resolver"
)

// Report holds all data needed to render the HTML report.
type Report struct {
	Domain    string
	Timestamp string
	Results   []resolver.Result
	Stats     Stats
}

// Stats holds aggregated counts from the scan results.
type Stats struct {
	Total     int
	Active    int
	Takeovers int
	CORSVuln  int
	SSLIssues int
	Wildcards int
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SubHawk Report — {{.Domain}}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:        #0d1117;
    --bg-card:   #161b22;
    --bg-table:  #161b22;
    --border:    #30363d;
    --text:      #c9d1d9;
    --text-muted:#8b949e;
    --accent:    #58a6ff;
    --green:     #3fb950;
    --red:       #f85149;
    --yellow:    #d29922;
    --purple:    #bc8cff;
    --row-green: rgba(63,185,80,0.08);
    --row-red:   rgba(248,81,73,0.12);
    --row-yellow:rgba(210,153,34,0.10);
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    padding: 0 0 48px;
  }

  /* ── Header ── */
  header {
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    padding: 24px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
  }
  header h1 {
    font-size: 22px;
    font-weight: 600;
    color: var(--accent);
    letter-spacing: -0.3px;
  }
  header h1 span { color: var(--text); }
  .header-meta {
    font-size: 12px;
    color: var(--text-muted);
    text-align: right;
  }
  .header-meta strong { color: var(--text); }

  /* ── Main layout ── */
  main { max-width: 1600px; margin: 0 auto; padding: 32px 32px 0; }

  /* ── Stat cards ── */
  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }
  .card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 16px;
    text-align: center;
  }
  .card .value {
    font-size: 32px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 6px;
  }
  .card .label {
    font-size: 12px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }
  .card.total   .value { color: var(--accent); }
  .card.active  .value { color: var(--green); }
  .card.takeover .value { color: var(--red); }
  .card.cors    .value { color: var(--yellow); }
  .card.ssl     .value { color: var(--purple); }
  .card.wildcard .value { color: var(--text-muted); }

  /* ── Search box ── */
  .search-bar {
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .search-bar input {
    flex: 1;
    max-width: 420px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    font-size: 14px;
    padding: 8px 12px;
    outline: none;
    transition: border-color 0.15s;
  }
  .search-bar input::placeholder { color: var(--text-muted); }
  .search-bar input:focus { border-color: var(--accent); }
  .result-count { font-size: 13px; color: var(--text-muted); }

  /* ── Table ── */
  .table-wrap {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    white-space: nowrap;
  }
  thead {
    background: #1c2128;
  }
  thead th {
    padding: 10px 14px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }
  tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background 0.1s;
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: rgba(88,166,255,0.05); }
  tbody tr.row-active   { background: var(--row-green); }
  tbody tr.row-takeover { background: var(--row-red); }
  tbody tr.row-cors     { background: var(--row-yellow); }
  tbody tr.row-takeover:hover { background: rgba(248,81,73,0.18); }
  tbody tr.row-cors:hover     { background: rgba(210,153,34,0.16); }
  tbody tr.row-active:hover   { background: rgba(63,185,80,0.13); }
  td {
    padding: 9px 14px;
    font-size: 13px;
    color: var(--text);
    vertical-align: top;
    max-width: 260px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  td.subdomain {
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 12px;
    color: var(--accent);
    font-weight: 600;
    max-width: 280px;
  }
  td.ips {
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 11px;
    color: var(--text-muted);
    max-width: 180px;
  }

  /* ── Badges ── */
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
  }
  .badge-green  { background: rgba(63,185,80,0.18);  color: var(--green); }
  .badge-red    { background: rgba(248,81,73,0.18);  color: var(--red); }
  .badge-yellow { background: rgba(210,153,34,0.18); color: #e3b341; }
  .badge-blue   { background: rgba(88,166,255,0.15); color: var(--accent); }
  .badge-purple { background: rgba(188,140,255,0.15); color: var(--purple); }
  .badge-gray   { background: rgba(139,148,158,0.15); color: var(--text-muted); }

  .score { font-weight: 700; }
  .score-high   { color: var(--green); }
  .score-medium { color: var(--yellow); }
  .score-low    { color: var(--red); }

  /* ── Legend ── */
  .legend {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-bottom: 12px;
    font-size: 12px;
    color: var(--text-muted);
  }
  .legend-item { display: flex; align-items: center; gap: 6px; }
  .legend-dot {
    width: 10px; height: 10px;
    border-radius: 2px;
    flex-shrink: 0;
  }
  .dot-active   { background: var(--green); opacity: 0.7; }
  .dot-takeover { background: var(--red); opacity: 0.7; }
  .dot-cors     { background: var(--yellow); opacity: 0.7; }

  /* ── Footer ── */
  footer {
    text-align: center;
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 40px;
  }
  footer a { color: var(--accent); text-decoration: none; }
</style>
</head>
<body>

<header>
  <h1>SubHawk <span>/ {{.Domain}}</span></h1>
  <div class="header-meta">
    <div>Scan completed</div>
    <strong>{{.Timestamp}}</strong>
  </div>
</header>

<main>

  <!-- Stats -->
  <section class="stats">
    <div class="card total">
      <div class="value">{{.Stats.Total}}</div>
      <div class="label">Total</div>
    </div>
    <div class="card active">
      <div class="value">{{.Stats.Active}}</div>
      <div class="label">Active</div>
    </div>
    <div class="card takeover">
      <div class="value">{{.Stats.Takeovers}}</div>
      <div class="label">Takeovers</div>
    </div>
    <div class="card cors">
      <div class="value">{{.Stats.CORSVuln}}</div>
      <div class="label">CORS</div>
    </div>
    <div class="card ssl">
      <div class="value">{{.Stats.SSLIssues}}</div>
      <div class="label">SSL Issues</div>
    </div>
    <div class="card wildcard">
      <div class="value">{{.Stats.Wildcards}}</div>
      <div class="label">Wildcards</div>
    </div>
  </section>

  <!-- Legend + search -->
  <div class="legend">
    <div class="legend-item"><div class="legend-dot dot-active"></div> Active</div>
    <div class="legend-item"><div class="legend-dot dot-takeover"></div> Takeover</div>
    <div class="legend-item"><div class="legend-dot dot-cors"></div> CORS Vuln</div>
  </div>

  <div class="search-bar">
    <input type="text" id="searchInput" placeholder="Filter results…" oninput="filterTable()">
    <span class="result-count" id="resultCount"></span>
  </div>

  <!-- Results table -->
  <div class="table-wrap">
    <table id="resultsTable">
      <thead>
        <tr>
          <th>Subdomain</th>
          <th>IPs</th>
          <th>Cloud</th>
          <th>Status</th>
          <th>Title</th>
          <th>WAF</th>
          <th>Headers Score</th>
          <th>CORS</th>
          <th>SSL</th>
          <th>Takeover</th>
          <th>Admin Panels</th>
          <th>JS Secrets</th>
        </tr>
      </thead>
      <tbody>
        {{range .Results}}
        <tr class="{{rowClass .}}">
          <td class="subdomain">{{.Subdomain}}</td>
          <td class="ips">{{joinStrings .IPs}}</td>
          <td>{{if .Cloud}}<span class="badge badge-blue">{{.Cloud}}</span>{{else}}<span class="badge badge-gray">—</span>{{end}}</td>
          <td>
            {{if .Takeover}}
              <span class="badge badge-red">Takeover</span>
            {{else if .Active}}
              <span class="badge badge-green">Active</span>
            {{else}}
              <span class="badge badge-gray">Inactive</span>
            {{end}}
          </td>
          <td>{{if .HTTP}}{{.HTTP.Title}}{{end}}</td>
          <td>{{if .WAF}}<span class="badge badge-purple">{{.WAF}}</span>{{else}}—{{end}}</td>
          <td>
            {{if .SecurityHeaders}}
              <span class="score {{scoreClass .SecurityHeaders.Score}}">{{.SecurityHeaders.Score}}/7</span>
            {{else}}—{{end}}
          </td>
          <td>
            {{if .CORS}}
              {{if .CORS.Vulnerable}}
                <span class="badge badge-yellow">Vuln</span>
              {{else}}
                <span class="badge badge-green">OK</span>
              {{end}}
            {{else}}—{{end}}
          </td>
          <td>
            {{if .TLS}}
              {{if .TLS.Expired}}
                <span class="badge badge-red">Expired</span>
              {{else if .TLS.SelfSigned}}
                <span class="badge badge-yellow">Self-signed</span>
              {{else if .TLS.HostnameMismatch}}
                <span class="badge badge-yellow">Mismatch</span>
              {{else if .TLS.WeakProtocol}}
                <span class="badge badge-yellow">Weak</span>
              {{else if .TLS.Valid}}
                <span class="badge badge-green">OK</span>
              {{else}}
                <span class="badge badge-red">Invalid</span>
              {{end}}
            {{else}}—{{end}}
          </td>
          <td>
            {{if .Takeover}}
              <span class="badge badge-red">{{.Takeover.Service}}</span>
            {{else}}—{{end}}
          </td>
          <td>
            {{if .AdminPanels}}
              <span class="badge badge-yellow">{{len .AdminPanels}}</span>
            {{else}}—{{end}}
          </td>
          <td>
            {{if .JS}}
              {{if .JS.Secrets}}
                <span class="badge badge-red">{{len .JS.Secrets}}</span>
              {{else}}
                <span class="badge badge-gray">0</span>
              {{end}}
            {{else}}—{{end}}
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>

</main>

<footer>
  <p>Generated by <a href="https://github.com/cyb3r3xpl0it/subhawk">SubHawk</a></p>
</footer>

<script>
(function () {
  function filterTable() {
    var input = document.getElementById('searchInput');
    var filter = input.value.toLowerCase();
    var tbody = document.getElementById('resultsTable').getElementsByTagName('tbody')[0];
    var rows = tbody.getElementsByTagName('tr');
    var visible = 0;
    for (var i = 0; i < rows.length; i++) {
      var text = rows[i].textContent || rows[i].innerText;
      if (text.toLowerCase().indexOf(filter) > -1) {
        rows[i].style.display = '';
        visible++;
      } else {
        rows[i].style.display = 'none';
      }
    }
    document.getElementById('resultCount').textContent = visible + ' of ' + rows.length + ' results';
  }

  // expose globally for oninput attribute
  window.filterTable = filterTable;

  // initialise count on load
  filterTable();
})();
</script>

</body>
</html>`

// rowClass returns the CSS class for a result table row.
func rowClass(r resolver.Result) string {
	if r.Takeover != nil {
		return "row-takeover"
	}
	if r.CORS != nil && r.CORS.Vulnerable {
		return "row-cors"
	}
	if r.Active {
		return "row-active"
	}
	return ""
}

// scoreClass returns a CSS class based on the security-headers score (out of 7).
func scoreClass(score int) string {
	switch {
	case score >= 6:
		return "score-high"
	case score >= 3:
		return "score-medium"
	default:
		return "score-low"
	}
}

// joinStrings joins a slice of strings with ", ".
func joinStrings(ss []string) string {
	return strings.Join(ss, ", ")
}

// computeStats derives Stats from a slice of results.
func computeStats(results []resolver.Result) Stats {
	s := Stats{Total: len(results)}
	for _, r := range results {
		if r.Active {
			s.Active++
		}
		if r.Takeover != nil {
			s.Takeovers++
		}
		if r.CORS != nil && r.CORS.Vulnerable {
			s.CORSVuln++
		}
		if r.TLS != nil && (!r.TLS.Valid || r.TLS.Expired || r.TLS.SelfSigned || r.TLS.HostnameMismatch || r.TLS.WeakProtocol) {
			s.SSLIssues++
		}
		if r.IsWildcard {
			s.Wildcards++
		}
	}
	return s
}

// Generate creates a standalone HTML report file at the given path.
func Generate(domain string, results []resolver.Result, outputPath string) error {
	funcMap := template.FuncMap{
		"rowClass":    rowClass,
		"scoreClass":  scoreClass,
		"joinStrings": joinStrings,
		"len":         func(v interface{}) int { return lenOf(v) },
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	data := Report{
		Domain:    domain,
		Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Results:   results,
		Stats:     computeStats(results),
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

// lenOf returns the length of slices used inside the template.
func lenOf(v interface{}) int {
	switch t := v.(type) {
	case []resolver.AdminPanel:
		return len(t)
	case []string:
		return len(t)
	default:
		return 0
	}
}
