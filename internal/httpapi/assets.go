package httpapi

import "net/http"

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) js(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	_, _ = w.Write([]byte(appJS))
}

func (s *Server) css(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	_, _ = w.Write([]byte(appCSS))
}

const indexHTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>桥梁振动告警研判闭环</title><link rel="stylesheet" href="/static/style.css"></head><body><main><h1>桥梁振动告警研判工作台</h1><p>从告警接收、波形复核到现场核验和归档关闭。</p><button onclick="loadCases()">刷新案件</button><div id="cases"></div></main><script src="/static/app.js"></script></body></html>`
const appJS = `async function loadCases(){const r=await fetch('/api/cases');const d=await r.json();const a=d.items||d;document.getElementById('cases').innerHTML=a.map(c=>'<article><b>'+ (c.case_id||c.CaseID)+'</b> '+(c.status||c.Status)+' · 风险 '+(c.risk_level||c.RiskLevel)+' · revision '+(c.revision||c.Revision)+'</article>').join('')}loadCases();`
const appCSS = `body{font-family:system-ui;background:#f4f7fb;color:#1f2937;margin:0}main{max-width:960px;margin:40px auto;background:white;padding:28px;border-radius:12px;box-shadow:0 4px 20px #ccd}button{padding:8px 16px;background:#1769aa;color:#fff;border:0;border-radius:6px}article{padding:14px;border-bottom:1px solid #ddd}`
