# Reasonably Secure Electron

_"In the face of ambiguity, refuse the temptation to guess."_ -The Zen of Python

Electron is often regarded as insecure by design. While this reputation is not entirely undeserved -make no mistake Electron has sharp edges- like any application security comes down to good engineering and software developement practices.

## Electron & Kin

[Electron](https://electronjs.org/) is a cross-platform framework for developing desktop applications using "web" technologies like HTML, JavaScript, and CSS. Electron has become very popular in recent years for its ease of use, empowering developers to quickly develope generally good looking, responsive, cross-platform desktop applications. Applications major tech companies like Microsoft Teams, VSCode, Slack, Atom, Spotify, and even secure messaging apps like Signal all use Electron or similar "native web" application frameworks. Electron did not start this trend, embedded webviews have been around for sometime. For example, iMessage is developed using embedded WebKit webviews, which have been [available on MacOS and iOS](https://developer.apple.com/documentation/webkit/wkwebview) for years. Similarly, JavaFX supports embedable WebKit and [Windows has IE objects](https://msdn.microsoft.com/en-us/windows/desktop/aa752084) that can be embedded in 3rd party applications.

There is however an important design change that occured with newer hipster Chrome-based frameworks like Electron and NodeWebKit; in the older frameworks the programmer generally had to selectively expose functionality or objects to the "web context" -that is the JavaScript execution context inside the webview. However, in Electron and kin the unsandboxed NodeJS APIs are _enabled by default_ and the developer must opt-out of this functionality regardless if the application even uses such functionality.

## Out of the Browser Into the Fire

This change has led to a significant increase in the impact a Cross-site Scripting (XSS) bug can have, since the attacker will gain access to the NodeJS APIs. Back in 2016 [Matt Bryant](https://twitter.com/IAmMandatory), [Shubs Shah](https://twitter.com/infosec_au), and I release some research on finding and exploiting these vulnerabilities in Electron and other native web frameworks. We demonstrating remote code execution vulnerabilities in Textual IRC, Azure Storage Explorer, and multiple markdown editors, as well as a flaw that allowed [remote disclosure of all iMessage data](https://know.bishopfox.com/blog/2016/04/if-you-cant-break-crypto-break-the-client-recovery-of-plaintext-imessage-data) on MacOS, and created a cross-platform self-propegating worm in RocketChat in our presentation at [Kiwicon](https://www.kiwicon.org/).

There's a common misconception that the proper fix for a Cross-site Scripting is sanitizing user input. The notation that sanitizing user input can concretely fix an XSS issue is untrue, the only proper fix for XSS is _contextual_ output encoding. That said, it's still a good idea to sanitize user input so do that too (and be sure you're sanatize using a whitelist, not a blacklist) --but you need to ensure it's done _in addition to proper output encoding_. A good rule of thumb is: "sanitize input, encode output," but what does "contextual encoding" entail?

### Bloodhound AD

Bloodhound is an incredibly powerful tool for analyzing the structure of Active Directory deployments, and finding ways to exploit the various privilege relationships therein. The attacker (or defender) runs a ingestor script the dumps data from Active Directory into JSON, the JSON is the parsed into a Neo4j database and an Electron GUI can be used to query and view the results in a nice graph view.

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
