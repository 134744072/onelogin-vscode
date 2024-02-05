const vscode = require("vscode");
const crypto = require('crypto');
const http = require('http');
const https = require('https');
let status,context; // ugly global var
exports.activate = async function (ctx) {
    context = ctx;
    status = vscode.window.createStatusBarItem('onelogin');
    status.show();
    statusRender();
    context.subscriptions.push(
        status,
        vscode.commands.registerCommand("olog.login", getSeed),
        vscode.commands.registerCommand("olog.logout", deleteSeed),
        vscode.commands.registerCommand("olog.generate", getToken),
    );
}
const hex2dec = (s) => parseInt(s, 16);
const dec2hex = (s) => (s < 15.5 ? "0" : "") + Math.round(s).toString(16);
const leftpad = (s, len, pad) => (len + 1 >= s.length) ? Array(len + 1 - s.length).join(pad) + s : s;
const fetch = (url, opt, body) => new Promise((resolve, reject) => {
	const client = url.startsWith('http://') ? http : https;
	if (client === https) process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0;
	const chunks = [], req = client.request(url, opt, res => {
		if (res.statusCode > 300) return reject(res);
		res.on('data', chunk => chunks.push(chunk));
		res.on('end', () => resolve(Buffer.concat(chunks)));
	}).on('error', reject);
	if (body) req.write(body);
	req.end();
});
function base32tohex(base32) {
    const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    let hex = "";
    base32 = base32.replace(/=+$/, "")
    for (let i = 0; i < base32.length; i++) {
        let val = base32chars.indexOf(base32.charAt(i).toUpperCase())
        if (val === -1) throw new Error("Invalid base32 character in key")
        bits += leftpad(val.toString(2), 5, "0")
    }
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        let chunk = bits.substr(i, 8)
        hex = hex + leftpad(parseInt(chunk, 2).toString(16), 2, "0")
    }
    return hex
}
async function statusRender(msg, duration = 3000) {
    const attr = {
        tooltip: "Get OneLogin OTP",
        command: await context.secrets.get("seed") ? "olog.generate" : "olog.login",
        text: await context.secrets.get("seed") ? '$(key)' : `$(key) Activate OneLogin`,
    };
    if (!msg) return Object.assign(status, attr);
    Object.assign(status, msg);
    setTimeout(async () => Object.assign(status, attr), duration);
}
async function getToken(options = { period: 30, algorithm: "SHA1", digits: 6, now: Date.now() }) {
    const seed = await context.secrets.get("seed");
    if (!seed) return vscode.commands.showInformationMessage('Please first setup OneLogin');
    const epoch = Math.floor(options.now / 1000.0);
    const time = leftpad(dec2hex(Math.floor(epoch / options.period)), 16, "0");
    const hmac = crypto.createHmac(options.algorithm, new Buffer.from(base32tohex(seed), 'hex'))
        .update(new Buffer.from(time, 'hex')).digest('hex');
    const offset = hex2dec(hmac.substring(hmac.length - 1));
    const otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec("7fffffff")) + "";
    const out = otp.substr(Math.max(otp.length - options.digits, 0), options.digits);
    await vscode.env.clipboard.writeText(out);
    statusRender({ text: `$(check) ${out} copied to clipboard` });
}
async function getSeed() {
    await vscode.window.showInformationMessage(`In next page: click "Activate" then "Can't scan QR?"`, `Open Page`);
    await vscode.env.openExternal(vscode.Uri.parse("https://airbus.onelogin.com/profile2/mfa/add"));
    const registration_id = await vscode.window.showInputBox({
        ignoreFocusOut: true,
        placeHolder: 'Format: 02-9876543',
        title: `9 digit code from "Activate" > "can't scan" popup`,
        validateInput: (str) => str.match(/^\d\d-\d\d\d\d\d\d\d$/) ? '' : 'Format shall be dd-ddddddd'
    });
    const data = new URLSearchParams({ registration_id, platform: 'gcm' }).toString();
    const json = await fetch("https://airbus.onelogin.com/api/internal/v2/otp/devices", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-length': data.length,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    }, data);
    const seed = JSON.parse(json).seed;
    await context.secrets.store("seed", seed);
    vscode.window.showInformationMessage(`Click 🔑 in status bar to generate a key`);
    statusRender();
}
async function deleteSeed() {
    await context.secrets.delete("seed");
    statusRender();
}
