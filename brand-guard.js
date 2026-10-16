/* BrandGuard v1: offline brand lookalike detection. No warning never means "safe". */
(function(root) {
"use strict";
const brands = Object.freeze([
  { name:"Suno", domain:"suno.com", aliases:["suno","sunoai"] },
  { name:"OpenAI", domain:"openai.com", aliases:["openai"] },
  { name:"ChatGPT", domain:"chatgpt.com", aliases:["chatgpt"] },
  { name:"GitHub", domain:"github.com", aliases:["github"] },
  { name:"Google", domain:"google.com", aliases:["google"] },
  { name:"Microsoft", domain:"microsoft.com", aliases:["microsoft"] },
  { name:"YouTube", domain:"youtube.com", aliases:["youtube"] },
  { name:"Discord", domain:"discord.com", aliases:["discord"] },
  { name:"Hugging Face", domain:"huggingface.co", aliases:["huggingface"] }
]);
const multipartSuffixes = new Set([
  "co.uk","org.uk","ac.uk","com.au","net.au","co.jp","com.cn",
  "com.br","co.in","co.nz","com.sg","com.hk"
]);
const baitSuffixes = /^(?:app|ai|login|signin|account|secure|support|official|verify|music|generator)$/;
function token(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}
function officialHost(host, domain) {
  return host === domain || host.endsWith("." + domain);
}
function baseLabel(host) {
  const parts = host.split(".");
  if (parts.length < 2) return "";
  const suffix = parts.slice(-2).join(".");
  return parts[parts.length - (multipartSuffixes.has(suffix) ? 3 : 2)] || "";
}
function oneEdit(a, b) {
  if (a === b) return true;
  if (Math.abs(a.length - b.length) > 1) return false;
  let i=0, j=0, edits=0;
  while (i<a.length && j<b.length) {
    if (a[i] === b[j]) { i++; j++; continue; }
    if (++edits > 1) return false;
    if (a.length > b.length) i++;
    else if (b.length > a.length) j++;
    else { i++; j++; }
  }
  return edits + Number(i<a.length || j<b.length) <= 1;
}
function mentioned(label, brand) {
  const text = String(label || "").normalize("NFKC").toLowerCase();
  return brand.aliases.some(alias =>
    new RegExp("(^|[^a-z0-9])" + alias + "($|[^a-z0-9])", "i").test(text));
}
function warning(brand, host, reason) {
  return { status:"warning", brand:brand.name, hostname:host,
    expectedDomain:brand.domain, reason };
}
function analyze(href, displayText="") {
  let url;
  try { url = new URL(href); } catch { return {status:"none"}; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return {status:"none"};
  const host=url.hostname.toLowerCase().replace(/\.$/,"");
  const base=token(baseLabel(host));
  const label=String(displayText || "").slice(0,400);
  for (const brand of brands) {
    if (officialHost(host,brand.domain)) continue;
    if (host.includes(brand.domain+".")) {
      return warning(brand,host,"Official domain appears inside an unrelated hostname.");
    }
    if (url.username && url.username.toLowerCase().includes(brand.domain)) {
      return warning(brand,host,"Official domain appears in URL credentials, not the hostname.");
    }
    const quoted=brand.domain.replace(/\./g,"\\.");
    const urlClaim=new RegExp("^\\s*(?:https?:\\/\\/)?(?:www\\.)?"+quoted+"(?:$|[/?#\\s])","i");
    if (urlClaim.test(label)) {
      return warning(brand,host,"Visible link address claims the official domain but points elsewhere.");
    }
    const titleMentionsBrand=mentioned(label,brand);
    const subLabels=host.split(".").slice(0,-2);
    if (titleMentionsBrand && subLabels.some(s=>brand.aliases.includes(token(s)))) {
      return warning(brand,host,"Brand-like subdomain is hosted under a different domain.");
    }
    for (const alias of brand.aliases) {
      if (base === alias) {
        return warning(brand,host,"Brand-like name is registered under a different domain.");
      }
      if (alias.length>=5 && base.length>=5 && oneEdit(base,alias)) {
        return warning(brand,host,"Domain spelling closely resembles a known brand.");
      }
      if (titleMentionsBrand && alias.length>=4 && base.length>=4 && oneEdit(base,alias)) {
        return warning(brand,host,"Linked title and similar domain suggest brand confusion.");
      }
      if (titleMentionsBrand && base.startsWith(alias) && baitSuffixes.test(base.slice(alias.length))) {
        return warning(brand,host,"Brand name combined with an official-looking qualifier.");
      }
    }
    if (titleMentionsBrand && host.split(".").some(p=>p.startsWith("xn--"))) {
      return {status:"notice",brand:brand.name,hostname:host,expectedDomain:brand.domain,
        reason:"Internationalized domain. Verify its identity before signing in."};
    }
  }
  return {status:"none"};
}
const api=Object.freeze({analyze,brands});
root.LHPBrandGuard=api;
if (typeof module !== "undefined" && module.exports) module.exports=api;
})(typeof globalThis !== "undefined" ? globalThis : this);
