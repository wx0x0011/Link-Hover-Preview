const assert = require("node:assert/strict");
const { analyze } = require("../brand-guard.js");
const cases = [
  ["Suno official","https://suno.com","Suno AI","none"],
  ["Suno subdomain","https://app.suno.com/create","Suno AI","none"],
  ["Bing lookalike","https://sunnoai.com/app","Suno AI: Create Songs Instantly","warning"],
  ["Alternate near-brand","https://sunoai.com","Suno AI App","warning"],
  ["False official subdomain","https://suno.com.evil.example/login","Suno","warning"],
  ["Lookalike subdomain","https://suno.example.org","Suno AI App","warning"],
  ["Link text mismatch","https://example.org","https://suno.com","warning"],
  ["Unrelated commentary","https://news.example.org/review-suno","Review of Suno","none"],
  ["Unrelated name","https://sumo.com","Wrestling","none"],
  ["GitHub lookalike","https://githuub.com","GitHub","warning"],
  ["Google official","https://accounts.google.com","Google","none"],
  ["Hugging Face official","https://huggingface.co","Hugging Face","none"],
  ["Other scheme","mailto:help@suno.com","Suno","none"],
  ["Punycode domain","https://xn--abc-def.example","Suno","notice"]
];
for (const [name,href,label,expected] of cases) {
  assert.equal(analyze(href,label).status,expected,name);
}
console.log("BrandGuard passed " + cases.length + " cases");
