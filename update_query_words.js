const fs = require('fs');
let code = fs.readFileSync('app.js', 'utf8');

const regex = /if \(def\.screenName\) queryWords\.push\(def\.screenName\.toLowerCase\(\)\);\s*if \(def\.title\) queryWords\.push\(def\.title\.toLowerCase\(\)\);/g;

const repl = `if (def.screenName) {
    let name = def.screenName.toLowerCase();
    // Strip extension if it has one (e.g., .java, .groovy, .json)
    if (name.includes('.')) name = name.substring(0, name.lastIndexOf('.'));
    queryWords.push(name);
  }
  if (def.title) {
    let t = def.title.toLowerCase();
    if (t.includes('.')) t = t.substring(0, t.lastIndexOf('.'));
    queryWords.push(t);
  }`;

code = code.replace(regex, repl);
fs.writeFileSync('app.js', code);
console.log('Fixed extension stripping for queryWords');
