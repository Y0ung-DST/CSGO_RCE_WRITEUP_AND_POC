Counter-Strike Global Offsets: Reliable Remote Code Execution
=============================================================

* * * * *

One of the factors contributing to Counter-Strike Global Offensive’s
(herein “CS:GO”) massive popularity is the ability for anyone to host
their own community server. These community servers are free to download
and install and allow for a high grade of customization. Server
administrators can create and utilize custom assets such as maps,
allowing for innovative game modes.

However, this design choice opens up a large attack surface. Players can
connect to potentially malicious servers, exchanging complex game
messages and binary assets such as textures.

We’ve managed to find and exploit two bugs that, when combined, lead to
reliable remote code execution on a player’s machine when connecting to
our malicious server. The first bug is an information leak that enabled
us to break ASLR in the client’s game process. The second bug is an
out-of-bounds access of a global array in the
`.data` section of one of the
game’s loaded modules, leading to control over the instruction pointer.


---------------------------------------------------------------------------------------------------------

Players can join community servers using a user friendly server browser
built into the game:

![](https://secret.club/assets/csgo_rce/serverlist.png)

Once the player joins a server, their game client and the community
server start talking to each other. As security researchers, it was our
task to understand the network protocol used by CS:GO and what kind of
messages are sent so that we could look for vulnerabilities.

As it turned out, CS:GO uses its own UDP-based protocol to serialize,
compress, fragment, and encrypt data sent between clients and a server.
We won’t go into detail about the networking code, as it is irrelevant
to the bugs we will present.

More importantly, this custom UDP-based protocol carries
`Protobuf` serialized payloads.
[Protobuf](https://developers.google.com/protocol-buffers) is a
technology developed by Google which allows defining messages and
provides an API for serializing and deserializing those messages.

Here is an example of a protobuf message defined and used by the CS:GO
developers:

``` c
message CSVCMsg_VoiceInit {
    optional int32 quality = 1;
    optional string codec = 2;
    optional int32 version = 3 [default = 0];
}
```

We found this message definition by doing a Google search after having
discovered CS:GO utilizes Protobuf. We came across the
[SteamDatabase](https://github.com/SteamDatabase/Protobufs/) GitHub
repository containing a list of Protobuf message definitions.

As the name of the message suggests, it’s used to initialize some kind
of voice-message transfer of one player to the server. The message body
carries some parameters, such as the codec and version used to interpret
the voice data.

[Developing a CS:GO proxy]
--------------------------------------------------------------------------------------------------------------

Having this list of messages and their definitions enabled us to gain
insights into what kind of data is sent between the client and server.
However, we still had no idea in which order messages would be sent and
what kind of values were expected. For example, we knew that a message
exists to initialize a voice message with some codec, but we had no idea
which codecs are supported by CS:GO.

For this reason, we developed a proxy for CS:GO that allowed us to view
the communication in real-time. The idea was that we could launch the
CS:GO game and connect to any server through the proxy and then dump any
messages received by the client and sent to the server. For this, we
reverse-engineered the networking code to decrypt and unpack the
messages.

We also added the ability to modify the values of any message that would
be sent/received. Since an attacker ultimately controls any value in a
Protobuf serialized message sent between clients and the server, it
becomes a possible attack surface. We could find bugs in the code
responsible for initializing a connection without reverse-engineering it
by mutating interesting fields in messages.

The following GIF shows how messages are being sent by the game and
dumped by the proxy in real-time, corresponding to events such as
shooting, changing weapons, or moving:

![](https://secret.club/assets/csgo_rce/csgo_proxy.gif)

Equipped with this tooling, it was now time for us to discover bugs by
flipping some bits in the protobuf messages.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

We discovered that a field in the
`CSVCMsg_SplitScreen` message,
that can be sent by a (malicious) server to a client, can lead to an OOB
access which subsequently leads to a controlled virtual function call.

The definition of this message is:

``` {.highlight}
message CSVCMsg_SplitScreen {
    optional .ESplitScreenMessageType type = 1 [default = MSG_SPLITSCREEN_ADDUSER];
    optional int32 slot = 2;
    optional int32 player_index = 3;
}
```

`CSVCMsg_SplitScreen` seemed
interesting, as a field called `player_index` is controlled by the server. However, contrary to
intuition, the `player_index`
field is not used to access an array, the `slot` field is. As it turns out, the
`slot` field is used as an index
for the array of splitscreen player objects located in the
`.data` segment of
`engine.dll` file without *any*
bounds checks.

Looking at the crash we could already observe some interesting facts:

1.  The array is stored in the `.data`{.language-plaintext
    .highlighter-rouge} section within `engine.dll`{.language-plaintext
    .highlighter-rouge}
2.  After accessing the array, an indirect function call on the accessed
    object occurs

The following screenshot of decompiled code shows how
`player_splot` was used without
any checks as an index. If the first byte of the object was not
`1`, a branch is entered:

![](https://secret.club/assets/csgo_rce/reversed1.png)

The bug proved to be quite promising, as a few instructions into the
branch a vtable is dereferenced and a function pointer is called. This
is shown in the next screenshot:

![](https://secret.club/assets/csgo_rce/reversed2.png)

We were very excited about the bug as it seemed highly exploitable,
given an info leak. Since the pointer to an object is obtained from a
global array within `engine.dll`, which at the time of writing is a
`6MB` binary, we were confident
that we could find a pointer to data we control. Pointing the
aforementioned object to attacker controlled data would yield arbitrary
code execution.

However, we would still have to fake a vtable at a known location and
then point the function pointer to something useful. Due to this
constraint, we decided to look for another bug that could lead to an
info leak.

[Uninitialized memory in HTTP downloads leads to information disclosure]
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

As mentioned earlier, server admins can create servers with any number
of customizations, including custom maps and sounds. Whenever a player
joins a server with such customizations, files behind the customizations
need to be transferred. Server admins can create a list of files that
need to be downloaded for each map in the server’s *playlist*.

During the connection phase, the server sends the client the URL of a
HTTP server where necessary files should be downloaded from. For each
custom file, a cURL request would be created. Two options that were set
for each request piqued our interested:
`CURLOPT_HEADERFUNCTION` and
`CURLOPT_WRITEFUNCTION`. The
former allows a callback to be registered that is called for each HTTP
header in the HTTP response. The latter allows registering a callback
that is triggered whenever body data is received.

The following screenshot shows how these options are set:

![](https://secret.club/assets/csgo_rce/reversed3.png)

We were interested in seeing how Valve developers handled incoming HTTP
headers and reverse engineered the function we named
`CurlHeaderCallback()`.

It turned out that the `CurlHeaderCallback()` simply parsed the
`Content-Length` HTTP header and
allocated an uninitialized buffer on the heap accordingly, as the
`Content-Length` should
correspond to the size of the file that should be downloaded.

The `CurlWriteCallback()` would
then simply write received data to this buffer.

Finally, once the HTTP request finished and no more data was to be
received, the buffer would be written to disk.

We immediately noticed a flaw in the parsing of the HTTP header
`Content-Length`: As the
following screenshot shows, a case sensitive compare was made.

![](https://secret.club/assets/csgo_rce/reversed4.png)

Case sensitive search for the `Content-Length` header.

This compare is flawed as HTTP headers can be lowercase as well. This is
only the case for Linux clients as they use cURL and then do the
compare. On Windows the client just assumes that the value returned by
the Windows API is correct. This yields the same bug, as we can just
send an arbitrary `Content-Length` header with a small response body.

We set up a HTTP server with a Python script and played around with some
HTTP header values. Finally, we came up with a HTTP response that
triggers the bug:

``` {.highlight}
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 1337
content-length: 0
Connection: closed
```

When a client receives such a HTTP response for a file download, it
would recognize the first `Content-Length` header and allocate a buffer of size
`1337`. However, a second
`content-length` header with
size `0` follows. Although the
CS:GO code misses the second `Content-Length` header due to its case sensitive search and still
expects `1337` bytes of body
data, cURL uses the last header and finishes the request immediately.

On Windows, the API just returns the first header value even though the
response is ill-formed. The CS:GO code then writes the allocated buffer
to disk, along with all uninitialized memory contents, including
pointers, contained within the buffer.

Although it appears that CS:GO uses the Windows API to handle the HTTP
downloads on Windows, the exact same HTTP response worked and allowed us
to create files of arbitrary size containing uninitialized memory
contents on a player’s machine.

A server can then request these files through the
`CNETMsg_File` message. When a
client receives this message, they will upload the requested file to the
server. It is defined as follows:

``` {.highlight}
message CNETMsg_File {
    optional int32 transfer_id = 1;
    optional string file_name = 2;
    optional bool is_replay_demo_file = 3;
    optional bool deny = 4;
}
```

Once the file is uploaded, an attacker controlled server could search
the file’s contents to find pointers into
`engine.dll` or heap pointers to
break ASLR. We described this step in detail in our appendix section
`Breaking ASLR`.

[Putting it all together: ConVars as a gadget]
------------------------------------------------------------------------------------------------------------------------------------------------------

To further enable customization of the game, the server and client
exchange `ConVar`s, which are
essentially configuration options.

Each ConVar is managed by a global object, stored in
`engine.dll`. The following code
snippet shows a simplified definition of such an object which is used to
explain why ConVars turned out to be a powerful gadget to help exploit
the OOB access:

    struct ConVar {
        char *convar_name;
        int data_len;
        void *convar_data;
        int color_value;
    };

A community server can update its `ConVar` values during a match and notify the client by
sending the `CNETMsg_SetConVar`
message:

``` {.highlight}
message CMsg_CVars {
    message CVar {
        optional string name = 1;
        optional string value = 2;
        optional uint32 dictionary_name = 3;
    }

    repeated .CMsg_CVars.CVar cvars = 1;
}

message CNETMsg_SetConVar {
    optional .CMsg_CVars convars = 1;
}
```

These messages consist of a simple key/value structure. When comparing
the message definition to the `struct ConVar` definition, it is correct to assume that the
entirely attacker-controllable `value` field of the ConVar message is copied to the
client’s heap and a pointer to it is stored in the
`convar_value` field of a
`ConVar` object.

As we previously discussed, the OOB access in
`CSVCMsg_SplitScreen` occurs in
an array of pointers to objects. Here is the decompilation of the code
in which the OOB access occurs as a reminder:

![](https://secret.club/assets/csgo_rce/reversed5.png)

Since the array and all `ConVars` are located in the `.data` section of `engine.dll`, we can reliably set the
`player_slot` argument such that
the `ptr_to_object` points to a
`ConVar` value which we
previously set. This can be illustrated as follows:

We also mentioned earlier that a few instructions after the OOB access a
virtual method on the object is called. This happens as usual through a
vtable dereference. Here is the code again as a reminder:

![](https://secret.club/assets/csgo_rce/reversed6.png)

Since we control the contents of the object through the
`ConVar`, we can simply set the
vtable pointer to any value. In order to make the exploit 100% reliable,
it would make sense to use the info leak to point back into the
`.data` section of
`engine.dll` into controlled
data.

Luckily, some `ConVars` are
interpreted as color values and expect a 4 byte (**R**ed **B**lue
**G**reen **A**lpha) value, which can be attacker controlled. This value
is stored directly in the `color_value` field in above `struct ConVar` definition. Since the CS:GO process on Windows is
32-bit, we were able to use the color value of a
`ConVar` to fake a pointer.

If we use the fake object’s vtable pointer to point into the
`.data` section of
`engine.dll`, such that the
called method overlaps with the `color_value`, we can finally hijack the `EIP` register and redirect control flow arbitrarily. This
chain of dereferences can be illustrated as follows:

[ROP chain to RCE]
===============================================================================================

With ASLR broken and us having gained arbitrary instruction pointer
control, all that was left to do was build a ROP chain that finally lead
to us calling `ShellExecuteA` to
execute arbitrary system commands.

![](https://media.discordapp.net/attachments/635278809741918218/879754592882151454/unknown.png)

[Poc]
===================================================================================

https://www.youtube.com/watch?v=rNQn--9xR1Q&ab_channel=SecretClub

[Breaking ASLR]
-----------------------------------------------------------------------------------------

In the
`Uninitialized memory in HTTP downloads leads to information disclosure` section, we showed how the HTTP download allowed us
to view arbitrarily sized chunks of uninitialized memory in a client’s
game process.

We discovered another message that seemed quite interesting to us:
`CSVCMsg_SendTable`. Whenever a
client received such a message, it would allocate an object with
attacker-controlled integer on the heap. Most importantly, the first 4
bytes of the object would contain a vtable pointer into
`engine.dll`.

``` python
def spray_send_table(s, addr, nprops):
    table = nmsg.CSVCMsg_SendTable()
    table.is_end = False
    table.net_table_name = "abctable"
    table.needs_decoder = False

    for _ in range(nprops):
        prop = table.props.add()
        prop.type = 0x1337ee00
        prop.var_name = "abc"
        prop.flags = 0
        prop.priority = 0
        prop.dt_name = "whatever"
        prop.num_elements = 0
        prop.low_value = 0.0
        prop.high_value = 0.0
        prop.num_bits = 0x00ff00ff

    tosend = prepare_payload(table, 9)
    s.sendto(tosend, addr)
```

The Windows heap is kind of nondeteministic. That is, a
`malloc -> free -> malloc` combo
will not yield the same block. Thankfully, Saar Amaar published his
[great research](https://github.com/saaramar/Deterministic_LFH) about
the Windows heap, which we consulted to get a better understanding about
our exploit context.

We came up with a spray to allocate many arrays of
`SendTable` objects with markers
to scan for when we uploaded the files back to the server. Because we
can choose the size of the array, we chose a not so commonly alloacted
size to avoid interference with normal game code. If we now deallocate
all of the sprayed arrays at once and then let the client download the
files the chance of one of the files to hit a previously sprayed chunk
is relativly high.

In practice, we almost always got the leak in the first file and when we
didn’t we could simply reset the connection and try again, as we have
not corrupted the program state yet. In order to maximize success, we
created four files for the exploit. This ensures that at least one of
them succeeds and otherwise simply try again.

The following code shows how we scanned the received memory for our
sprayed object to find the `SendTable` vtable which will point into
`engine.dll`.

``` python
files_received.append(fn)
pp = packetparser.PacketParser(leak_callback)

for i in range(len(data) - 0x54):
    vtable_ptr = struct.unpack('<I', data[i:i+4])[0]
    table_type = struct.unpack('<I', data[i+8:i+12])[0]
    table_nbits = struct.unpack('<I', data[i+12:i+16])[0]
    if table_type == 0x1337ee00 and table_nbits == 0x00ff00ff:
        engine_base = vtable_ptr - OFFSET_VTABLE 
        print(f"vtable_ptr={hex(vtable_ptr)}")
        break
```
https://secret.club/2021/05/13/source-engine-rce-join.html
