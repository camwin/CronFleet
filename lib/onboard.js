const fs = require('fs');
const path = require('path');

function renderOnboardScript(publicUrl, token, pubKey) {
  const tpl = fs.readFileSync(path.join(__dirname, '..', 'templates', 'onboard.sh.tpl'), 'utf8');
  return tpl
    .replace(/__CONTROL_PLANE_URL__/g, publicUrl)
    .replace(/__HOST_TOKEN__/g, token)
    .replace(/__SSH_PUB_KEY__/g, pubKey);
}

module.exports = { renderOnboardScript };
