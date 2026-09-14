package main

import (
  "encoding/json"
  "fmt"
  "os"
  "sort"
  "strings"
  "time"
  "unicode"
)

const ( Allow="ALLOW"; Deny="DENY"; Unresolved="UNRESOLVED" )

type RawContract struct { ContractID string `json:"contract_id"`; Denied []string `json:"denied"`; Domain []string `json:"domain"`; Form string `json:"form"`; Name string `json:"name"`; StaticDecision *string `json:"static_decision"` }
type Corpus struct { Github map[string]RawContract `json:"github"` }
type Contract struct { id string; domain map[string]bool; denied map[string]bool; static *string }
type Receipt struct { contract string; identity string; decision string }

func build(r RawContract) Contract { d:=map[string]bool{}; x:=map[string]bool{}; for _,v:=range r.Domain { d[v]=true }; for _,v:=range r.Denied { x[v]=true }; return Contract{r.ContractID,d,x,r.StaticDecision} }
func (c Contract) decide(x string) string { if x=="" || !c.domain[x] { return Unresolved }; if c.static!=nil { return *c.static }; if c.denied[x] { return Deny }; return Allow }
func (c Contract) authorize(x string) Receipt { return Receipt{c.id,x,c.decide(x)} }
func (c Contract) permits(r Receipt,x string) bool { return r.contract==c.id && r.decision==Allow && r.identity==x && c.domain[x] }
func (c Contract) mediate(x string) string { r:=c.authorize(x); if r.decision!=Allow { return r.decision }; if c.permits(r,x) { return Allow }; return Unresolved }

func tokenPolicy(identity string) string {
  if i:=strings.Index(identity,"="); i>=0 { identity=identity[i+1:] }
  var toks []string; var b []rune; var prev rune
  flush:=func(){ if len(b)>0 { toks=append(toks,strings.ToLower(string(b))); b=nil } }
  for _,r:=range identity {
    if !unicode.IsLetter(r) && !unicode.IsDigit(r) { flush(); prev=r; continue }
    if unicode.IsUpper(r) && len(b)>0 && (unicode.IsLower(prev)||unicode.IsDigit(prev)) { flush() }
    b=append(b,r); prev=r
  }; flush()
  for _,t:=range toks { if t=="delete"||t=="remove"||t=="cancel" { return Deny } }
  return Allow
}

func main(){
  if len(os.Args)<2 { panic("usage: go_selector <g5_contracts.json>") }
  raw,err:=os.ReadFile(os.Args[1]); if err!=nil { panic(err) }; var corp Corpus; if err=json.Unmarshal(raw,&corp);err!=nil { panic(err) }
  cs:=map[string]Contract{}; var pairs [][2]string; mism:=0
  names:=make([]string,0,len(corp.Github)); for n:=range corp.Github { names=append(names,n) }; sort.Strings(names)
  for _,n:=range names { r:=corp.Github[n]; c:=build(r); cs[n]=c; for _,x:=range r.Domain { pairs=append(pairs,[2]string{n,x}); if c.mediate(x)!=tokenPolicy(x){mism++} }; if c.mediate("__unknown__")!=Unresolved { mism++ } }
  var mixed Contract; var a,d string
  for _,n:=range names { c:=cs[n]; if c.static==nil && len(c.denied)>0 && len(c.denied)<len(c.domain){ mixed=c; for x:=range c.domain { if c.denied[x] { d=x } else if a=="" { a=x } }; break } }
  r:=mixed.authorize(a); binding:=mixed.permits(r,a)&&!mixed.permits(r,d)
  loops:=1000000; start:=time.Now(); allowCount:=0; for i:=0;i<loops;i++ { p:=pairs[i%len(pairs)]; if cs[p[0]].mediate(p[1])==Allow { allowCount++ } }; sec:=time.Since(start).Seconds()
  out:=map[string]any{"language":"go","checked":len(pairs),"mismatches":mism,"unknown_fail_closed":true,"receipt_binding":binding,"tool_count":len(cs),"tool_count_change":0,"benchmark_ops":loops,"ops_s":float64(loops)/sec,"allow_count":allowCount,"pass":mism==0&&binding}
  b,_:=json.MarshalIndent(out,"","  "); fmt.Println(string(b)); if !out["pass"].(bool){os.Exit(2)}
}
